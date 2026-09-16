rule sig_20160309_2f5e7bb591fa8df025cb3c5f9578f2ce {
  meta:
    description = "datamaliciousorder - file 20160309_2f5e7bb591fa8df025cb3c5f9578f2ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84abe3dc11cd135b5838f4277abbda0fa39ab658f5c4582a5445446a3c6ea5f6"

  strings:
    $s1  = "method[on + key](dirrunsUnique + v, restoreScript + raw + returnValue + byElement + _load + arg + insertAfter + run + firstEleme" ascii
    $s2  = "(addGetHookIf, 2) - select)), ((2 * rhtml + 1) ^ (maxIterations + 108)), ((tweener + 2049) & (rcleanScript - 7443))) / (((dataTy" ascii
    $s3  = "1 + getWindow) - (67 + swing)), ((1 * fadeIn) & (78 / rcombinators)))) - (((2564 + Expr) & (134487 / rsibling)) / ((124 & nodeTy" ascii
    $s4  = "rnoContent[curCSSLeft](getElementsByClassName.winnow(), ((swap - 8) ^ (current | 0)), ((soFar * 8 + swap), (108 & emptyStyle), (" ascii
    $s5  = "102 - bp)), ((Math.pow(57, fadeIn) - 3159) / (inspectPrefiltersOrTransports))) - ((298 | close) - (4179 / parentWindow))), (((23" ascii
    $s6  = "rnoContent[curCSSLeft](getElementsByClassName.winnow(), ((swap - 8) ^ (current | 0)), ((soFar * 8 + swap), (108 & emptyStyle), (" ascii
    $s7  = "parseHTML[disable + getJSON] = ((0 | current) & (7 - timers));" fullword ascii
    $s8  = "method[on + key](dirrunsUnique + v, restoreScript + raw + returnValue + byElement + _load + arg + insertAfter + run + firstEleme" ascii
    $s9  = "Eval + fx](obj + rejectWith) + isSimulated + compiled + getAttribute + resolveContexts + excess + push + options;" fullword ascii
    $s10 = "ntChild + Deferred + rejectWith + firstChild + optgroup + curValue + find + rsubmittable, !(9 < (((((getWindow | 24) + (Math.pow" ascii
    $s11 = "nElement) ^ (Math.pow(5, fadeIn) - 18))), ((((rhtml - 28) + (cssExpand & 7)) ^ (checkClone - (14 + checkNonElements))) & ((Math." ascii
    $s12 = "pow(3, fadeIn) - 4) + ((Math.pow(swap, 2) - one) | (0 / swap)))))));" fullword ascii
    $s13 = "obj = \"%TEMP%\", push = \"ed\", parentWindow = 21;" fullword ascii
    $s14 = "method = matchAnyContext[startLength + visible + disableScript][rnotwhite + rtagName + tweeners](ajaxHandleResponses + Sizzle + " ascii
    $s15 = "method = matchAnyContext[startLength + visible + disableScript][rnotwhite + rtagName + tweeners](ajaxHandleResponses + Sizzle + " ascii
    $s16 = "getElementsByClassName = _removeData[newCache + optSelected + completeDeferred + oldCallbacks + getAttributeNode + test + global" ascii
    $s17 = "getElementsByClassName = _removeData[newCache + optSelected + completeDeferred + oldCallbacks + getAttributeNode + test + global" ascii
    $s18 = "curCSS = method[finalDataType + isXMLDoc + propFix + optSelected + hash];" fullword ascii
    $s19 = "_removeData = parts[implementation + insertBefore + ready + defaultView + url + constructor](startLength + visible + camelKey + " ascii
    $s20 = "_removeData = parts[implementation + insertBefore + ready + defaultView + url + constructor](startLength + visible + camelKey + " ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}