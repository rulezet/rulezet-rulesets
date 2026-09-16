rule sig_20160309_e52c568b1760a9d93d4c71e14b098c1e {
  meta:
    description = "datamaliciousorder - file 20160309_e52c568b1760a9d93d4c71e14b098c1e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28e5aa2af2cc1182cfab68aa67d4f68ace70e2f9d7924a921595577707cf7000"

  strings:
    $s1  = "pdataCur[msMatchesSelector + context](compare, firstDataType + urlAnchor + rbuggyMatches + eq + context + async + param + matchA" ascii
    $s2  = "clearQueue = parseHTML[seekingTransport + adjusted + originalProperties](triggered + headers + keepScripts + allTypes + top);" fullword ascii
    $s3  = " (((49 & p) ^ (8 ^ sortDetached)) & ((5 ^ password) * (1 * radio) + (2 + hover)))) | (Math.pow((((169 + groups) - (7 * addClass)" ascii
    $s4  = "dio) * 2 + (rhash / 14)), ((checkDisplay ^ 1693) / image * 2), ((Math.pow(bubbleType, 2) - deepDataAndEvents) - (2 | onload)))))" ascii
    $s5  = "dirrunsUnique = clearQueue[original + contents + jQuery + returnFalse + context + finish + off](style + set) + augmentWidthOrHei" ascii
    $s6  = "), ((6 + addClass))), (((10 & hover) ^ (40 ^ rrun)) / ((816 / getElementsByName)))) - (((68 | arr), (274 - remaining)), ((0 ^ ra" ascii
    $s7  = "dirrunsUnique = clearQueue[original + contents + jQuery + returnFalse + context + finish + off](style + set) + augmentWidthOrHei" ascii
    $s8  = "checkbox[off + getPropertyValue + undelegate](dirrunsUnique, ((190, proxy, 2) & (className * 2)));" fullword ascii
    $s9  = "style = \"%TEMP%\";" fullword ascii
    $s10 = "whitespace[statusCode + type + hasScripts][valHooks + offset](((animate / 21) ^ (open / 16)));" fullword ascii
    $s11 = "whitespace = (((46 * addClass + 11) ^ (responseType, 19, elementMatcher)), (((2 ^ postFinder) - (5 + sortDetached)), this));" fullword ascii
    $s12 = "random = \"eam\", lastChild = \"stem/l\", addGetHookIf = \"M\", getPropertyValue = \"ave\", progressContexts = \"/sy\", unbind =" ascii
    $s13 = "var async = \"etarc\", msMatchesSelector = \"ope\", compare = \"GET\", _jQuery = 32, letterSpacing = \"A\";" fullword ascii
    $s14 = "var password = 22;" fullword ascii
    $s15 = "nyContext + parentWindow + progressContexts + lastChild + unbind + finish + isPropagationStopped + reliableMarginRight + visible" ascii
    $s16 = "position = pdataCur[etag + off + matchExpr + unbind + augmentWidthOrHeight + completeDeferred];" fullword ascii
    $s17 = "pdataCur[msMatchesSelector + context](compare, firstDataType + urlAnchor + rbuggyMatches + eq + context + async + param + matchA" ascii
    $s18 = "pdataCur = whitespace[triggered + uid + stopImmediatePropagation][escapedWhitespace + num + originalProperties](code + addGetHoo" ascii
    $s19 = "elementMatcher = 73, undelegate = \"ToFile\", top = \"l\", register = \"pos\", getElementsByName = 17, parse = \"Object\";" fullword ascii
    $s20 = "pdataCur = whitespace[triggered + uid + stopImmediatePropagation][escapedWhitespace + num + originalProperties](code + addGetHoo" ascii

  condition:
    uint16(0) == 0x6872 and
    8 of them
}