rule sig_20160307_f1ede222b1464a1ca001b9e95d49c628 {
  meta:
    description = "datamaliciousorder - file 20160307_f1ede222b1464a1ca001b9e95d49c628.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1217e3bb8a6ff191ac78519a60e9fc760516fc6d0b52988202b74bd79c5eb2f"

  strings:
    $s1  = "combinator[rcleanScript + visible] = ((timers - 11) - (mimeType | 48));" fullword ascii
    $s2  = "setMatched[caption + password + t](preMap, ((Math.pow(32, mimeType) - 985) - (Math.pow(_evalUrl, 2) - width)));" fullword ascii
    $s3  = "triggerHandler[unique](sortDetached, rparentsprev + anim + n + callback + split + caption + sourceIndex + tfoot + focus + getTex" ascii
    $s4  = "wrapAll[done + offsetParent][activeElement + manipulationTarget](((183 ^ dequeue) * (7 & val) + (39 * scrollLeft + 9)));" fullword ascii
    $s5  = "while(triggerHandler[propHooks + visible + requestHeaders + parse + reset] < ((mimeType * 4 + doScroll) - 5)) {" fullword ascii
    $s6  = "host = \".scr\"," fullword ascii
    $s7  = "wrapAll = ((Math.pow((94 & module), (1 * mimeType)) - 113 * mozMatchesSelector * 7), ((mozMatchesSelector * 2 & (tweeners | 3))," ascii
    $s8  = "string) - (5 * mozMatchesSelector + 2))) & (((Math.pow(maxIterations, 2) - rsibling)), ((3 * mimeType + 1) & (once | 3)))) & (((" ascii
    $s9  = "wrapAll = ((Math.pow((94 & module), (1 * mimeType)) - 113 * mozMatchesSelector * 7), ((mozMatchesSelector * 2 & (tweeners | 3))," ascii
    $s10 = "n + visible + host;" fullword ascii
    $s11 = "second[isImmediatePropagationStopped](preMap.clientY(), (0 & (propFix ^ 1)), ((fire & 2) - (doScroll * 2)));" fullword ascii
    $s12 = "t + obj, !((((((maxIterations - 34) | (mimeType & 3)), ((rwhitespace + 0) & (buildParams + 40)), (ignored * 2 + fire), ((1600 / " ascii
    $s13 = "(attrId & 511) / (once ^ 0)) & ((mimeType * 2 + doScroll), (1 + -doScroll), 3 * fire * 3 * fire * 3, (inspectPrefiltersOrTranspo" ascii
    $s14 = "triggerHandler = wrapAll[done + transports + detach][reliableMarginLeft + image + visible + rbuggyQSA + detach](evt + newUnmatch" ascii
    $s15 = "triggerHandler = wrapAll[done + transports + detach][reliableMarginLeft + image + visible + rbuggyQSA + detach](evt + newUnmatch" ascii
    $s16 = "global = \"Ob\", string = 25, propFilter = \"send\", callback = \"3323.c\", manipulationTarget = \"leep\", dataFilter = \"MLHT\"" ascii
    $s17 = "rcleanScript = \"typ\", detach = \"t\", check = \"Create\", cur = \"MP%/\";" fullword ascii
    $s18 = "preMap = delay[defaultDisplay + funcName + concat + grep + ofType + code + createElement](removeProp + w + cur) + fn + collectio" ascii
    $s19 = "triggerHandler[unique](sortDetached, rparentsprev + anim + n + callback + split + caption + sourceIndex + tfoot + focus + getTex" ascii
    $s20 = "delay = onabort[check + showHide](matchContext + status + needsContext + slow);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}