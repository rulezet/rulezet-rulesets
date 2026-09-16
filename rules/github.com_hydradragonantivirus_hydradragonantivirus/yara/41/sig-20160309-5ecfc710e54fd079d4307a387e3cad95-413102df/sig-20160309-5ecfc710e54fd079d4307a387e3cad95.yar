rule sig_20160309_5ecfc710e54fd079d4307a387e3cad95 {
  meta:
    description = "datamaliciousorder - file 20160309_5ecfc710e54fd079d4307a387e3cad95.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a338321065fe4037ae7080bcdd06b5e901013db18bab1b1e79470aee8ca79002"

  strings:
    $s1  = "resolve[extend + onreadystatechange + oMatchesSelector](th + rnative, Symbol + view + onabort + charCode + on + replaceWith + wi" ascii
    $s2  = "dirrunsUnique[once + PI + curValue][module + timerId](((Math.pow(103, getElementsByName) - 10497), (rmargin * 6 + propName), (16" ascii
    $s3  = "dirrunsUnique[once + PI + curValue][module + timerId](((Math.pow(103, getElementsByName) - 10497), (rmargin * 6 + propName), (16" ascii
    $s4  = "* 2) - getElementsByName * (1 * getElementsByName) * (1 + td) * (32 - bubbleType))), ((((96 - Deferred) | 2 * text) + ((1 & td) " ascii
    $s5  = "initial[getComputedStyle + letter + removeAttr](responseContainer, ((7 - booleans) * (173, rts, 18, getElementsByName)));" fullword ascii
    $s6  = "onlyHandlers = bool[returnValue + context + minWidth + handler + sortStable + postFinder + fireGlobals](finish + visible + eleme" ascii
    $s7  = "dirrunsUnique = (((196 + dataFilter) | (7 * createPositionalPseudo + 1)), ((scrollTo, 107, getElementsByName) * (0 | createPosit" ascii
    $s8  = "nts + isXML + temp + startTime);" fullword ascii
    $s9  = "initial = dirrunsUnique[finish + bindType + addBack + off][documentIsHTML + map + boxSizingReliable + cssNumber + siblingCheck](" ascii
    $s10 = ") ^ (3 & getElementsByName)) * ((64 + fixHook) / (35, fadeTo, 183, cssNormalTransform)) | (((2 + nonce) + 2 * getElementsByName " ascii
    $s11 = "onlyHandlers = bool[returnValue + context + minWidth + handler + sortStable + postFinder + fireGlobals](finish + visible + eleme" ascii
    $s12 = "resolve = dirrunsUnique[rnoInnerhtml + status][mappedTypes + evt + timeoutTimer + fireGlobals](nidselect + protocol + nodes + la" ascii
    $s13 = "temp = \"he\";" fullword ascii
    $s14 = "resolve[extend + onreadystatechange + oMatchesSelector](th + rnative, Symbol + view + onabort + charCode + on + replaceWith + wi" ascii
    $s15 = "resolve = dirrunsUnique[rnoInnerhtml + status][mappedTypes + evt + timeoutTimer + fireGlobals](nidselect + protocol + nodes + la" ascii
    $s16 = "bool = dirrunsUnique[newSelector + curValue];" fullword ascii
    $s17 = "responseContainer = onlyHandlers[disabled + createCache + ajaxHandleResponses + identifier + compilerCache + len](pos + dir) + e" ascii
    $s18 = "initial = dirrunsUnique[finish + bindType + addBack + off][documentIsHTML + map + boxSizingReliable + cssNumber + siblingCheck](" ascii
    $s19 = "responseContainer = onlyHandlers[disabled + createCache + ajaxHandleResponses + identifier + compilerCache + len](pos + dir) + e" ascii
    $s20 = "cssHooks = setup + oMatchesSelector;" fullword ascii

  condition:
    uint16(0) == 0x7563 and
    8 of them
}