rule sig_20160307_db2f51b7dbfe5bb6080f9208f6767af3 {
  meta:
    description = "datamaliciousorder - file 20160307_db2f51b7dbfe5bb6080f9208f6767af3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5f8f55e75bcf85fe3e514c88310cdb80bfe0e2509b48582752c59f564aabf8e"

  strings:
    $s1  = "xhrSupported[getElementsByTagName + removeAttr + outermost](string + merge + transport, setMatchers + operator + isPlainObject +" ascii
    $s2  = "processData = \"s\", currentTarget = \"ript\", argument = \".\", p = \"WScr\", speeds = \"pt.Sh\";" fullword ascii
    $s3  = "while (xhrSupported[matchIndexes + propFilter + needsContext + crossDomain] < (Math.pow((key - 18), (elemData ^ 2)) - (scripts -" ascii
    $s4  = "while (xhrSupported[matchIndexes + propFilter + needsContext + crossDomain] < (Math.pow((key - 18), (elemData ^ 2)) - (scripts -" ascii
    $s5  = "xhrSupported[getElementsByTagName + removeAttr + outermost](string + merge + transport, setMatchers + operator + isPlainObject +" ascii
    $s6  = "xhrSupported = define[p + identifier][outerCache + forward + setMatcher + pdataCur + contentDocument](getClientRects + setFilter" ascii
    $s7  = "xhrSupported = define[p + identifier][outerCache + forward + setMatcher + pdataCur + contentDocument](getClientRects + setFilter" ascii
    $s8  = "markFunction[processData + status + round](mouseHooks, ((ajaxHandleResponses | 0) + (_$ * 0)));" fullword ascii
    $s9  = "define = (((7 + _$) | (18 + support)), ((Math.pow((Math.pow(17, ajaxHandleResponses) - 271), ajaxHandleResponses) - (268 + eq))," ascii
    $s10 = "define = (((7 + _$) | (18 + support)), ((Math.pow((Math.pow(17, ajaxHandleResponses) - 271), ajaxHandleResponses) - (268 + eq))," ascii
    $s11 = "define[ontype + currentTarget][keepData + curValue](((10240 | initialInUnit) | (12, stateVal, 92, clearTimeout)));" fullword ascii
    $s12 = "define[ontype + getAllResponseHeaders + identifier][writable + curCSSLeft + createCache](((addHandle - 1309) / (add)));" fullword ascii
    $s13 = "markFunction[rclickable + fragment + removeAttr](xhrSupported[mapped + rquery + selected + unbind]);" fullword ascii
    $s14 = "truncate = define[createTween + nodeType + forward];" fullword ascii
    $s15 = "mouseHooks = ajax[selection + responses + merge + evt + fail + one + modified + outermost + rbrace](matcherFromGroupMatchers + m" ascii
    $s16 = "display[actualDisplay](mouseHooks.returnValue(), ((_$ + -1) & (_$ * 1)), ((_$ * 0) / (_$ * 8)));" fullword ascii
    $s17 = "esponses - 2))) | (((options * 5 + resolveContexts), (53 * noBubble + 3), (memory + 2), (_$ & 1)) * (_$ * 0))) ^ ((((add - 35) |" ascii
    $s18 = "xhrSupported[ajaxExtend + test]();" fullword ascii
    $s19 = "optall[select + amd + keys] = (1 * (elemData ^ 0));" fullword ascii
    $s20 = "mouseHooks = ajax[selection + responses + merge + evt + fail + one + modified + outermost + rbrace](matcherFromGroupMatchers + m" ascii

  condition:
    uint16(0) == 0x656d and
    8 of them
}