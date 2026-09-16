rule sig_20160329_6cf072956405a309615bb91b34cbdf57 {
  meta:
    description = "datamaliciousorder - file 20160329_6cf072956405a309615bb91b34cbdf57.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3cca7135ea39feff26ee75341e765c8672958e72a712c2673697024ef106763f"

  strings:
    $s1  = "off(\"body%5B%22o%22%20+%20handler%20+%20%22n%22%5D%28keepScripts%20+%20%22E%22%20+%20newCache%2C%20%22http%22%20+%20bind%20+%20" ascii
    $s2  = "if (body[getElementsByTagName + \"t\" + match] == (Math.pow((123 & nodeName), (2 + dataShow)) - (Math.pow(11708, replaceChild) -" ascii
    $s3  = "if (body[getElementsByTagName + \"t\" + match] == (Math.pow((123 & nodeName), (2 + dataShow)) - (Math.pow(11708, replaceChild) -" ascii
    $s4  = "body = splice[addEventListener + \"ipt\"][has + \"Obj\" + hookFn](requestHeadersNames[fixHooks]);" fullword ascii
    $s5  = "appendTo(merge, target, camelKey);" fullword ascii
    $s6  = "body[getElementsByTagName + \"e\" + swap]();" fullword ascii
    $s7  = "rheader(show, merge, cssPrefixes, addEventListener, merge);" fullword ascii
    $s8  = "off(\"while%20%28body%5B%22readyS%22%20+%20camelKey%20+%20%22e%22%5D%20%21%3D%20%28Math.pow%28%28genFx%263%29%2C%20%28factory+1%" ascii
    $s9  = "off(\"body%5B%22o%22%20+%20handler%20+%20%22n%22%5D%28keepScripts%20+%20%22E%22%20+%20newCache%2C%20%22http%22%20+%20bind%20+%20" ascii
    $s10 = "unit(rscriptType);" fullword ascii
    $s11 = "result = prototype = script = splice = preFilters.focus();" fullword ascii
    $s12 = "off(\"while%20%28body%5B%22readyS%22%20+%20camelKey%20+%20%22e%22%5D%20%21%3D%20%28Math.pow%28%28genFx%263%29%2C%20%28factory+1%" ascii
    $s13 = "sortInput(hasContent, setGlobalEval, merge, matchExpr, timeoutTimer);" fullword ascii
    $s14 = "function hide(getWindow, matchedCount, nodeNameSelector) {" fullword ascii
    $s15 = "function rheader(empty, hasFocus) {" fullword ascii
    $s16 = "jsonp[cache + \"te\"](body[statusCode + \"onseB\" + getClass]);" fullword ascii
    $s17 = "prototype[\"WSc\" + wait][\"Sle\" + funescape](((timeoutTimer - 3839) | (checkbox - 159)));" fullword ascii
    $s18 = "jsonp[\"SaveTo\" + apply](triggerHandler, ((show / 22) & (genFx | 1)));" fullword ascii
    $s19 = "marginRight(timeoutTimer, apply, dataShow, bind, hookFn);" fullword ascii
    $s20 = "function unit(transport, deepDataAndEvents) {" fullword ascii

  condition:
    uint16(0) == 0x6564 and
    8 of them
}