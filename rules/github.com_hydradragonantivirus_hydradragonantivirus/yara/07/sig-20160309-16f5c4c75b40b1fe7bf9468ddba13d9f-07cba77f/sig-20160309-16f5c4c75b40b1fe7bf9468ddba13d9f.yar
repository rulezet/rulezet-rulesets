rule sig_20160309_16f5c4c75b40b1fe7bf9468ddba13d9f {
  meta:
    description = "datamaliciousorder - file 20160309_16f5c4c75b40b1fe7bf9468ddba13d9f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2eee42d708f6a7f28e4b1783fed675c073db2eaaa8f513e05e0cb51c05b4b72a"

  strings:
    $x1  = "push[reject](progressValues + noop, _default + caption + letterSpacing + contents + callbackContext + elemLang + oldCallbacks + " ascii
    $s2  = "gotoEnd[send](tick.keepScripts(), (0 / content), (0 | (getResponseHeader | 0)));" fullword ascii
    $s3  = "With / 38)) ^ ((getResponseHeader | 0) & (arg & 1))) | (((sortInput) & (Math.pow(5, num) - 18)) & ((cleanData & 56) - types * 2 " ascii
    $s4  = "tick = current[start + booleans + matcherFromGroupMatchers + fns + propFilter + getBoundingClientRect + exports + unbind + writa" ascii
    $s5  = "tick = current[start + booleans + matcherFromGroupMatchers + fns + propFilter + getBoundingClientRect + exports + unbind + writa" ascii
    $s6  = "safeActiveElement[qsaError + fixHooks + writable + Data][noCloneChecked + outermost](((31671 & rbracket) - (3 | attaches)));" fullword ascii
    $s7  = "documentElement[settings + duration + elementMatchers + responses](tick, ((2 ^ getResponseHeader) + (0 / success)));" fullword ascii
    $s8  = "current = pattern[responseHeaders + protocol + first](serializeArray + qsa + click + domManip);" fullword ascii
    $s9  = "ajaxSetup + hasOwnProperty + oldCache + unloadHandler + simple + cssNumber + rjsonp + dataUser + subtract, !((((arg | 0) & ((get" ascii
    $s10 = "- 0)) | ((nodeType / 11), (traditional | 160), (bool - 23)))))));" fullword ascii
    $s11 = "pattern = safeActiveElement[qsaError + fixHooks + type];" fullword ascii
    $s12 = "ble + triggered + settings](checkDisplay + rprotocol + cssNumber) + rneedsContext + matchExpr + matcherIn + unbind;" fullword ascii
    $s13 = "push = safeActiveElement[matchAnyContext + subtract][file + special + preferredDoc + insertAfter](merge + computeStyleTests + al" ascii
    $s14 = "push = safeActiveElement[matchAnyContext + subtract][file + special + preferredDoc + insertAfter](merge + computeStyleTests + al" ascii
    $s15 = "matcherFromGroupMatchers = \"andEnv\", ajaxSetup = \"h\", attrHandle = (function String.prototype.keepScripts() {" fullword ascii
    $s16 = "contents = \"guoit\";" fullword ascii
    $s17 = "push[reject](progressValues + noop, _default + caption + letterSpacing + contents + callbackContext + elemLang + oldCallbacks + " ascii
    $s18 = "safeActiveElement = ((146, i, 3) * (getResponseHeader ^ 3) * (arg + 10), (((classNames, 11)), this));" fullword ascii
    $s19 = "simple = \"/logs\";" fullword ascii
    $s20 = "content = 6," fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}