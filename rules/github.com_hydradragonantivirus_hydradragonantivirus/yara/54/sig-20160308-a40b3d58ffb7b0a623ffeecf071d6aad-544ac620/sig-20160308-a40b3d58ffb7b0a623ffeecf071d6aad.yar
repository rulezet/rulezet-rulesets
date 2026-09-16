rule sig_20160308_a40b3d58ffb7b0a623ffeecf071d6aad {
  meta:
    description = "datamaliciousorder - file 20160308_a40b3d58ffb7b0a623ffeecf071d6aad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81b4f3843465db44404d6ed1dc85bce2bb385cc9f2a340ad3d0497fc9836332d"

  strings:
    $s1  = "nType[getClass](keepData + matcherOut + exports, preFilter + adown + prefix + args + end + callback + toggle, !(unqueued == (((4" ascii
    $s2  = "2 - cleanData) * (23, udataOld, 3)) & ((setRequestHeader - 29) * (done | 0) - ((setMatched, 0, getWindow, 1) & (hasCompare * 1))" ascii
    $s3  = "while(nType[slow + makeArray] < ((0 & hasCompare) | (Math.pow(3, done) - 5))) {" fullword ascii
    $s4  = "addGetHookIf = \"Sc\", toArray = \"Create\", origType = \"ite\", isReady = \"ript.\", host = \"p\";" fullword ascii
    $s5  = "root = before[toArray + valueIsBorderBox + pointerenter](cssText + addGetHookIf + isReady + status + rtrim);" fullword ascii
    $s6  = "camelCase[caption + nodeValue + updateFunc + left][cur + host]((Math.pow((Math.pow(image, 2) - aup), (2 & done)) - 29 * cssShow " ascii
    $s7  = "camelCase[caption + nodeValue + updateFunc + left][cur + host]((Math.pow((Math.pow(image, 2) - aup), (2 & done)) - 29 * cssShow " ascii
    $s8  = "unshift[value + animate + map] = ((done + 3) - (ready & 7));" fullword ascii
    $s9  = ")) * ((((pseudo, 59, rneedsContext, 13) - (cssShow ^ 15)) & ((hasCompare * 1) | (hasCompare * 0))) + (((url / 2) / (hasCompare *" ascii
    $s10 = "hasFocus = \"send\", hidden = \"MLHTTP\", slow = \"ready\", url = 0, namespace = \"es\", left = \"t\";" fullword ascii
    $s11 = "camelCase = ((1 * cssShow) * (104 - type), (((41 ^ clientLeft), (250 - checkDisplay), (Math.pow(33, done) - 1028), (ready + 2))," ascii
    $s12 = "camelCase = ((1 * cssShow) * (104 - type), (((41 ^ clientLeft), (250 - checkDisplay), (Math.pow(33, done) - 1028), (ready + 2))," ascii
    $s13 = "preFilter = \"http:\";" fullword ascii
    $s14 = "nType[getClass](keepData + matcherOut + exports, preFilter + adown + prefix + args + end + callback + toggle, !(unqueued == (((4" ascii
    $s15 = "fadeOut = root[matcherOut + firstChild + DOMParser + safeActiveElement + useCache + isArray + location](prevAll + getJSON) + fas" ascii
    $s16 = "fadeOut = root[matcherOut + firstChild + DOMParser + safeActiveElement + useCache + isArray + location](prevAll + getJSON) + fas" ascii
    $s17 = "setMatched = 28, prevAll = \"%TEMP%\", isArray = \"trin\", udataOld = 174, inPage = \"M\", className = \"WS\";" fullword ascii
    $s18 = "outermostContext[urlAnchor + isImmediatePropagationStopped + newContext](fadeOut, (hasCompare * (0 | done)));" fullword ascii
    $s19 = "nType = camelCase[head + left][originalEvent + slideToggle + calculatePosition + pointerenter](inPage + position + protocol + hi" ascii
    $s20 = "outermostContext = camelCase[head + left][unique + calculatePosition + pointerenter](rejectWith + src + createButtonPseudo);" fullword ascii

  condition:
    uint16(0) == 0x7370 and
    8 of them
}