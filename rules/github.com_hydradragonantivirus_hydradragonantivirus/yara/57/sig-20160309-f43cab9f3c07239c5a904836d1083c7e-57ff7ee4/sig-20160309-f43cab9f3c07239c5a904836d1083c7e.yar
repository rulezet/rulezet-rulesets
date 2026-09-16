rule sig_20160309_f43cab9f3c07239c5a904836d1083c7e {
  meta:
    description = "datamaliciousorder - file 20160309_f43cab9f3c07239c5a904836d1083c7e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4276f85ce3cddd6576139a8c54b5ff2facd4e89492797f16b5a1ee0228c8bfd"

  strings:
    $x1  = "uniqueID[onreadystatechange + thead](completed, s + newDefer + radioValue + hasContent + responseHeaders + html + contentType + " ascii
    $s2  = "uniqueID = on[startTime + triggerHandler][root + type + self + rcssNum](click + addGetHookIf + rnoContent + active);" fullword ascii
    $s3  = "removeEventListener[soFar](delay.rscriptTypeMasked(), ((filter & 1) * ajaxSetup), (12 - second));" fullword ascii
    $s4  = "next + realStringObj + mappedTypes + Expr + relatedTarget + matched + triggered, !(((((107, filter) & (0 & (ajaxSetup / 9))) ^ (" ascii
    $s5  = "delay = raw[charset + parseJSON + fx + postSelector + hash + isPropagationStopped + oMatchesSelector + msFullscreenElement](subt" ascii
    $s6  = "always[trigger + parent + thead] = ((ajaxSetup | 0) / (matcherFromTokens, 71, insertBefore, 16));" fullword ascii
    $s7  = "(computeStyleTests | 0) / (converters ^ 13))) * ((((stopQueue ^ 26) / (currentValue - 45)) ^ filter) + ((1 * ajaxSetup) | 0))) =" ascii
    $s8  = "triggered = \"g54\", trigger = \"pos\", properties = 127, rejectWith = \"WSc\", completed = \"GET\";" fullword ascii
    $s9  = "postSelector = \"onm\", parseJSON = \"xpand\", root = \"Cre\", thead = \"n\";" fullword ascii
    $s10 = "delay = raw[charset + parseJSON + fx + postSelector + hash + isPropagationStopped + oMatchesSelector + msFullscreenElement](subt" ascii
    $s11 = "risSimple = (function Object.prototype.rscriptTypeMasked() {" fullword ascii
    $s12 = "jsonpCallback = on[docElem + risSimple][superMatcher + createTween + diff + match](postMap + fixInput);" fullword ascii
    $s13 = "current = \"Shell\";" fullword ascii
    $s14 = "maxWidth = on[docElem + memory + appendTo];" fullword ascii
    $s15 = "on = (((47, bySet, 182, disabled) * 3 + (filter * 9)), (((ajaxSetup / 19) ^ cos), this));" fullword ascii
    $s16 = "raw = maxWidth[nodeType + safeActiveElement + match](rejectWith + using + current);" fullword ascii
    $s17 = "jsonpCallback[cssNumber + callbackContext](delay, (scale - 39));" fullword ascii
    $s18 = "hash = \"en\";" fullword ascii
    $s19 = "bindType[appendTo + cacheLength] = ((61 ^ unquoted), (27 ^ func), (99 & properties), 1);" fullword ascii
    $s20 = "always = bindType;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}