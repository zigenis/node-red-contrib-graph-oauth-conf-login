const fetch = require("node-fetch");

module.exports = function (RED) {
  var node;
  var flowContext;

  function GraphOnBehalfLoginNode(config) {
    RED.nodes.createNode(this, config)

    //Variables in Credentials are automatically added to this.config. Variables in defaults are stored in config.
    this.code = config.code
    this.scope = config.scope
    this.redirecturi = config.redirecturi
    this.encoding = config.encoding
    this.logintype = config.logintype
    this.refreshtimer = config.refreshtimer
    this.clientid = config.clientid
    this.tenantid = config.tenantid
    this.clientsecret = config.clientsecret

    node = this
    flowContext = node.context().flow

    node.on("input", async function (msg, send, done) {
      await Login(msg, send)

      if (done) {
        done()
      }
    })
  }

  //Entrance method of the node
  async function Login(msg, send) {
    node.log("Type of login: " + node.logintype)
    var isDelegated = node.logintype == "Delegated"

    if (node.clientid == undefined || node.clientid == "") {
      msg.payload = "Empty ClientId"
      send(msg)
      return
    }
    if (node.clientsecret == undefined || node.clientsecret == "") {
      msg.payload = "Empty ClientSecret"
      send(msg)
      return
    }
    if (node.tenantid == undefined || node.tenantid == "") {
      msg.payload = "Empty TenantId"
      send(msg)
      return
    }
    if (node.scope == "") {
      msg.payload = "Empty Scope"
      send(msg)
      return
    }

    if (isDelegated) {
      if (node.code == "") {
        msg.payload = "Empty Code"
        send(msg)
        return
      }
      if (node.redirecturi == "") {
        msg.payload = "Empty Redirect Uri"
        send(msg)
        return
      }
    }

    //Check if initial login or that data has changed in the node fields, which also means a new login
    node.log("Checking for login / refresh")
    node.refreshtoken = isDelegated
      ? flowContext.get("graph-DelegatedRefreshToken")
      : flowContext.get("graph-ApplicationAccessToken")
    var initiallogin = IsInitialLogin()

    //Inf initial login set the flow values for next time, if not, check for refresh window if delegated or return access token when using application permissions
    if (initiallogin) {
      SetInitialContext()
    } else if (isDelegated && NotExpired(isDelegated)) {
      msg.payload = "Refresh token still valid, no further action will be taken"
      node.log(msg.payload)
      msg.at = flowContext.get("graph-DelegatedAccessToken")
      msg.bearer = flowContext.get("graph-DelegatedBearerToken")
      msg.rt = flowContext.get("graph-DelegatedRefreshToken")
      send(msg)
      return
    } else if (!isDelegated && NotExpired(isDelegated)) {
      msg.payload =
        "Application access token still valid, no further action will be taken"
      node.log(msg.payload)
      msg.at = flowContext.get("graph-ApplicationAccessToken")
      msg.rt = msg.at
      msg.bearer = flowContext.get("graph-ApplicationBearerToken")
      send(msg)
      return
    }

    var response = await ExecuteLogin(initiallogin)
    node.log("Login done")

    if (response != undefined) {
      SetMessageResponse(msg, response, send)
    }
  }

  function NotExpired(isDelegated) {
    var expirationdate = isDelegated
      ? flowContext.get("graph-DelegatedRefreshTokenexpirationdate")
      : flowContext.get("graph-ApplicationExpirationDate")
    var flowRefreshTimer = isDelegated
      ? flowContext.get("graph-DelegatedRefreshTimer")
      : flowContext.get("graph-ApplicationRefreshTimer")
    var refreshtimer = node.refreshtimer
    var date = new Date()

    if (refreshtimer == undefined || refreshtimer == null || refreshtimer < 0) {
      refreshtimer = 0
    }

    if (
      flowRefreshTimer == undefined ||
      flowRefreshTimer == null ||
      flowRefreshTimer < 0
    ) {
      flowRefreshTimer = 0
    }

    if (flowRefreshTimer != refreshtimer) {
      node.log(
        "Refresh time changed. Old: " +
          flowRefreshTimer +
          " New: " +
          refreshtimer
      )

      if (isDelegated) {
        flowContext.set("graph-DelegatedRefreshTimer", refreshtimer)
      } else {
        flowContext.set("graph-ApplicationRefreshTimer", refreshtimer)
      }

      node.log("Timer change, performing refresh")
      return false
    }

    if (refreshtimer == 0) {
      node.log("Timer set to zero, performing refresh")
      return false
    }

    node.log("Expiration date: " + expirationdate + ". Current date: " + date)
    return expirationdate != undefined && expirationdate > date
  }

  //Timer object needs to be defined, otherwise we cannot kill the old timer
  var delegatedTimer
  var applicationTimer

  //THe actual to Graph, done after checking the values upon calling the node or when the refresh is called by the timer
  async function ExecuteLogin(initiallogin) {
    try {
      var form = ""
      var clientid = node.encoding
        ? encodeURIComponent(node.clientid)
        : node.clientid
      var clientsecret = node.encoding
        ? encodeURIComponent(node.clientsecret)
        : node.clientsecret
      var code = node.encoding ? encodeURIComponent(node.code) : node.code
      var tenantid = node.encoding
        ? encodeURIComponent(node.tenantid)
        : node.tenantid
      var redirecturi = node.encoding
        ? encodeURIComponent(node.redirecturi)
        : node.redirecturi
      var scope = node.encoding ? encodeURIComponent(node.scope) : node.scope
      var isDelegated = node.logintype == "Delegated"

      form =
        encodeURIComponent("client_id") +
        "=" +
        clientid +
        "&" +
        encodeURIComponent("client_secret") +
        "=" +
        clientsecret +
        "&" +
        encodeURIComponent("scope") +
        "=" +
        scope +
        "&" +
        encodeURIComponent("grant_type") +
        "="

      if (initiallogin == true || !isDelegated) {
        form = isDelegated
          ? form +
            encodeURIComponent("authorization_code") +
            "&" +
            encodeURIComponent("code") +
            "=" +
            code
          : form + encodeURIComponent("client_credentials")
      } else {
        var refreshToken = encodeURIComponent("refresh_token")
        //One is the grant_type and the other is the actual variable refresh_token
        form =
          form + rt + "&" + rt + "=" + encodeURIComponent(node.refreshtoken)
      }

      if (isDelegated) {
        form =
          form + "&" + encodeURIComponent("redirect_uri") + "=" + redirecturi
      }

      node.log("Used Encoding: " + node.encoding)
      var url =
        "https://login.microsoftonline.com/" + tenantid + "/oauth2/v2.0/token"

      //Use this for debugging
      //node.log("Full request: " + url + form);

      var response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Host: "login.microsoftonline.com",
        },
        body: form,
      }).then((response) => response.json())

      if (response.access_token != undefined) {
        var accesstoken = response.access_token
        var bearer = "Bearer " + accesstoken

        if (isDelegated) {
          flowContext.set("graph-DelegatedAccessToken", accesstoken)
          flowContext.set("graph-DelegatedBearerToken", bearer)
          flowContext.set("graph-DelegatedRefreshToken", response.refresh_token)
        } else {
          flowContext.set("graph-ApplicationAccessToken", accesstoken)
          flowContext.set("graph-ApplicationBearerToken", bearer)
        }

        SetTimer(isDelegated)
        node.log("Tokens set")
      } else {
        node.log("Error in response: " + response.error)
      }

      return response
    } catch (error) {
      node.log(error)
      return error
    }
  }

  function SetTimer(isDelegated) {
    var expirationdate = new Date()
    //Despite being a number in the UI, it is not an actual number, however + string is accepted in JS and will create some wonky results, so be sure to parse to int
    var refreshtimer = parseInt(node.refreshtimer)
    expirationdate.setMinutes(expirationdate.getMinutes() + refreshtimer)

    node.log("Setting Expiration date to: " + expirationdate)

    if (isDelegated) {
      flowContext.set(
        "graph-DelegatedRefreshTokenexpirationdate",
        expirationdate
      )

      //Unfortunately we cannot use timer as a parameter, js does not understand this and will not kill the old timer because it always sees it as a new timer, thus creating continous timers
      if (delegatedTimer) {
        node.log("Removing old delegated timer")
        clearInterval(delegatedTimer)
      }

      if (node.refreshtimer > 0) {
        node.log("Setting new Delegated timer")
        delegatedTimer = setInterval(function () {
          ExpirationCheck(expirationdate)
        }, 60000)
      } else {
        node.log("No timer specified")
      }
    } else {
      flowContext.set("graph-ApplicationExpirationDate", expirationdate)

      if (applicationTimer) {
        node.log("Removing old application timer")
        clearInterval(applicationTimer)
      }

      if (node.refreshtimer > 0) {
        node.log("Setting new application timer")
        applicationTimer = setInterval(function () {
          ExpirationCheck(expirationdate)
        }, 60000)
      } else {
        node.log("No timer specified")
      }
    }
  }

  //Log if value is changed, prompting a new login rather then a refresh
  function SetMessageResponse(msg, response, send) {
    if (response != null) {
      msg.payload = response
      var accesstoken = response.access_token

      if (response.access_token != undefined) {
        msg.at = accesstoken
        msg.rt =
          node.logintype == "Delegated" ? response.refresh_token : accesstoken
        msg.bearer = "Bearer " + accesstoken
      }
    }

    send(msg)
  }

  //Timer method
  async function ExpirationCheck(expirationdate) {
    node.log("Interval reached. Checking if refresh is required")

    var date = new Date()
    node.log("Expiration date: " + expirationdate + ". Current date: " + date)

    if (expirationdate != undefined && expirationdate > date) {
      node.log("Refresh token still valid, no further action will be taken")
      return
    }

    node.log("Expiration date has passed, refreshing token")
    var initiallogin = false
    await ExecuteLogin(initiallogin)
  }

  //Check if initial login or refresh is required
  function IsInitialLogin() {
    if (node.refreshtoken == undefined || node.refreshtoken == null) {
      node.log("(Refresh) Token not set, initial login")
      return true
    }

    if (node.logintype == "Delegated") {
      return IsInitialDelegatedLogin()
    }

    return IsInitialApplicationLogin()
  }

  //Check if initial login or refresh is required for delegated permissions
  function IsInitialDelegatedLogin() {
    var flowcode = flowContext.get("graph-DelegatedCode")
    var flowclientid = flowContext.get("graph-ClientID")
    var flowclientsecret = flowContext.get("graph-ClientSecret")
    var flowtenantid = flowContext.get("graph-TenantID")
    var flowredirecturi = flowContext.get("graph-DelegatedRedirectURI")
    var flowscope = flowContext.get("graph-DelegatedScope")

    if (node.code != flowcode) {
      LogChange("Code")
      return true
    }
    if (node.scope != flowscope) {
      LogChange("Scope")
      return true
    }
    if (flowclientid == undefined) {
      LogChange("ClientId")
      return true
    }
    if (flowclientsecret == undefined) {
      LogChange("ClientSecret")
      return true
    }
    if (flowtenantid == undefined) {
      LogChange("TenantId")
      return true
    }
    if (node.redirecturi != flowredirecturi) {
      LogChange("RedirectUri")
      return true
    }

    node.log("Checking if refresh is required")
    return false
  }

  //Check if initial login or refresh is required for application permissions
  function IsInitialApplicationLogin() {
    var flowclientid = flowContext.get("graph-ClientID")
    var flowclientsecret = flowContext.get("graph-ClientSecret")
    var flowtenantid = flowContext.get("graph-TenantID")
    var flowscope = flowContext.get("graph-ApplicationScope")

    if (node.scope != flowscope) {
      LogChange("Scope")
      return true
    }
    if (flowclientid == undefined) {
      LogChange("ClientId")
      return true
    }
    if (flowclientsecret == undefined) {
      LogChange("ClientSecret")
      return true
    }
    if (flowtenantid == undefined) {
      LogChange("TenantId")
      return true
    }

    node.log("Checking if refresh is required")
    return false
  }

  //Logging the value that has changed since the last time the node was called
  function LogChange(value) {
    node.log(value + " changed, performing new login")
  }

  //Setting the flows that need to be checked if they changed
  function SetInitialContext() {
    flowContext.set("graph-ClientID", node.clientid)
    flowContext.set("graph-ClientSecret", node.clientsecret)
    flowContext.set("graph-TenantID", node.tenantid)

    var refreshtimer =
      node.refreshtimer == undefined ||
      node.refreshtimer < 0 ||
      node.refreshtimer == null
        ? 0
        : node.refreshtimer

    if (node.logintype == "Delegated") {
      flowContext.set("graph-DelegatedCode", node.code)
      flowContext.set("graph-DelegatedRedirectURI", node.redirecturi)
      flowContext.set("graph-DelegatedScope", node.scope)
      flowContext.set("graph-DelegatedRefreshTimer", refreshtimer)
      return
    }

    flowContext.set("graph-ApplicationScope", node.scope)
    flowContext.set("graph-ApplicationRefreshTimer", refreshtimer)
  }

  //Credenitals need to be registered in the js as well, otherwise Node-Red will throw an error that it does not recognize these types
  RED.nodes.registerType(
    "node-red-contrib-graph-oauth-conf-login",
    GraphOnBehalfLoginNode,
    {
      credentials: {
        clientid: { type: "password" },
        clientsecret: { type: "password" },
        tenantid: { type: "password" },
      },
    }
  )
}
