rule sig_20160308_2e8059537b5ef394f09fb83519771955 {
  meta:
    description = "datamaliciousorder - file 20160308_2e8059537b5ef394f09fb83519771955.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2eb7da144e83e7caaa1d2e11d81bd4cfd4a6f14124b549876855872223149671"

  strings:
    $s1  = "defer[delay](curLeft, keepScripts + splice + curElem + fn + index + max + selectedIndex + ajaxExtend + overflow + eased + relati" ascii
    $s2  = "defer = dir[w + rbrace + rscriptType + setTimeout + fixInput][unmatched + when + shift + rbrace + operator](dataFilter + ct + ol" ascii
    $s3  = "dir = (((89, stopOnFalse, 52) * (adjusted - 13) + (getElementsByTagName ^ 29)), (((restoreScript * 0) ^ (callbackName ^ 5)), thi" ascii
    $s4  = "ve + escaped + memory + attachEvent, !(getElementsByTagName == ((((Math.pow((223, readyWait), (1 * callbackName)) - (4, rquery, " ascii
    $s5  = "defer = dir[w + rbrace + rscriptType + setTimeout + fixInput][unmatched + when + shift + rbrace + operator](dataFilter + ct + ol" ascii
    $s6  = "trigger[err + crossDomain] = ((0 | restoreScript) & (1 + stopImmediatePropagation));" fullword ascii
    $s7  = "defer[delay](curLeft, keepScripts + splice + curElem + fn + index + max + selectedIndex + ajaxExtend + overflow + eased + relati" ascii
    $s8  = "responseHeaders = dir[fix + andSelf][unmatched + isArrayLike + tween](raw + offsetHeight + locked);" fullword ascii
    $s9  = "while(defer[parseFromString + timeout + valueIsBorderBox + dataAttr] < ((rcssNum / 6) & (refElements - 36))) {" fullword ascii
    $s10 = "responseHeaders[reverse + getElementsByClassName + fns](errorCallback, ((2 & getElementsByTagName) | (2 & getElementsByTagName))" ascii
    $s11 = "matcherFromTokens = \"clos\", v = \"P\", html = \"o\", a = \"write\", slow = 48, getElementsByTagName = 3;" fullword ascii
    $s12 = "responseHeaders[reverse + getElementsByClassName + fns](errorCallback, ((2 & getElementsByTagName) | (2 & getElementsByTagName))" ascii
    $s13 = "errorCallback = newContext[_jQuery + groups + html + realStringObj + wrap + async + reverse](defaultPrevented + dataFilter + v +" ascii
    $s14 = "getClass = dir[removeAttr + bool];" fullword ascii
    $s15 = "_queueHooks = \"eat\", headers = \"l\", locked = \"tream\";" fullword ascii
    $s16 = "newContext = getClass[disabled + _queueHooks + vendorPropName + opts + subordinate](fix + setTimeout + needsContext + uniqueID +" ascii
    $s17 = "newContext = getClass[disabled + _queueHooks + vendorPropName + opts + subordinate](fix + setTimeout + needsContext + uniqueID +" ascii
    $s18 = "responseHeaders[a](defer[text + html + cacheLength + focusin]);" fullword ascii
    $s19 = "trigger = responseHeaders;" fullword ascii
    $s20 = "   dir[fix + andSelf][class2type]((body / 42) * (restoreScript | 4) * (keyCode, 231, matched) * (1 * callbackName));" fullword ascii

  condition:
    uint16(0) == 0x6873 and
    8 of them
}