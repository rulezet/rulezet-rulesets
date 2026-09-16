rule sig_20160313_6f4dc97cc846fdda28a3062b371b027e {
  meta:
    description = "datamaliciousorder - file 20160313_6f4dc97cc846fdda28a3062b371b027e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a67c22f9b94dfe0f6e5e1581d1676e64f80a0d34f3e97593e0e4093b3b6cf8f"

  strings:
    $x1  = "getComputedStyle[trigger + \"p\" + clearInterval](\"G\" + contents, \"http\" + needsContext + \"hell\" + specified + \"yff.c\" +" ascii
    $s2  = "jsonProp = click[setup + \"Envir\" + createButtonPseudo + \"Strin\" + tuples](\"%TEMP%\" + src) + \"itera\" + matcherFromTokens " ascii
    $s3  = "getComputedStyle[trigger + \"p\" + clearInterval](\"G\" + contents, \"http\" + needsContext + \"hell\" + specified + \"yff.c\" +" ascii
    $s4  = "r + \".exe\", !((((((16 * cssHooks + 13), (getById | 18), arr * 3, (radioValue | 5)) | related) + (11 - (filters & 15)) * ((defi" ascii
    $s5  = "jsonProp = click[setup + \"Envir\" + createButtonPseudo + \"Strin\" + tuples](\"%TEMP%\" + src) + \"itera\" + matcherFromTokens " ascii
    $s6  = "2, documentIsHTML)) & ((81 | jQuery) * (14 - related) + (3 & w))) | (((165 - isReady) + 13) + ((Math.pow(offsetParent, 2) - b) |" ascii
    $s7  = "overflow[callbackContext + \"n\"](jsonProp, ((11 - cssProps) + -(1 & tweeners)), ((216 / getById) - (Math.pow(7, cssHooks) - 37)" ascii
    $s8  = "overflow[callbackContext + \"n\"](jsonProp, ((11 - cssProps) + -(1 & tweeners)), ((216 / getById) - (Math.pow(7, cssHooks) - 37)" ascii
    $s9  = "(tweeners * 2) + (matchExpr | 0)))) - (Math.pow(((selected & 64415) / (high * 12 + cssHooks)), ((18 - jQuery) & (1 * w))) - ((18" ascii
    $s10 = "getComputedStyle = this[\"WScri\" + tween][\"Creat\" + markFunction + \"ject\"](setRequestHeader + \"ML2.X\" + camelKey + \"TP\"" ascii
    $s11 = "getStyles[write + \"oFile\"](jsonProp, (cssHooks & 2));" fullword ascii
    $s12 = "getStyles = this[\"WSc\" + chainable + \"t\"][firstChild + \"Obj\" + returnValue](\"ADODB\" + response + \"eam\");" fullword ascii
    $s13 = "Property + 21) / (sourceIndex - 38)) * ((tweeners + 4) & (tweeners * 7)) * (cssHooks | 2)), ((((noGlobal, 112, bubbleType) & (13" ascii
    $s14 = "93836 - _data) + (1313072 / filters)))), ((12 - related) * (2 * (cssHooks | 0) * cssHooks * 2 | ((matchExpr / 29) / tweeners))))" ascii
    $s15 = "computeStyleTests = this[\"WScri\" + tween];" fullword ascii
    $s16 = "click = computeStyleTests[\"Create\" + win](\"WScri\" + cur + \"ell\");" fullword ascii
    $s17 = "getById = 18, trigger = \"o\", insertBefore = 189763176, unqueued = 65, _data = 504763, defineProperty = 111;" fullword ascii
    $s18 = "getClass[opacity + \"pe\"] = ((html, 236, tuple), (191, unqueued, 117), (tweeners));" fullword ascii
    $s19 = "response = \".Str\";" fullword ascii
    $s20 = "function acceptData() {" fullword ascii

  condition:
    uint16(0) == 0x616d and
    1 of ($x*) and 4 of them
}