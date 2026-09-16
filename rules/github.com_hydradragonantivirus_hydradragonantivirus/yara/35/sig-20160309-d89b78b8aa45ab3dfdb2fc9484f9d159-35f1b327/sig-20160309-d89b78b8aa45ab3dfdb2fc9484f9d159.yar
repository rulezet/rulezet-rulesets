rule sig_20160309_d89b78b8aa45ab3dfdb2fc9484f9d159 {
  meta:
    description = "datamaliciousorder - file 20160309_d89b78b8aa45ab3dfdb2fc9484f9d159.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d2aa18dc6d79ee47a5dcc88b9bfe7c849d4498ae1b20e8c3eeec0a5596c1d2eb"

  strings:
    $s1  = "stateVal[pseudo](rlocalProtocol, iframe + defaultPrefilter + requestHeaders + matcherIn + createCache + caption + msg + response" ascii
    $s2  = "ng + completed + manipulationTarget + responses + triggered);" fullword ascii
    $s3  = "optDisabled = ((0 | superMatcher) * (Math.pow(22, superMatcher) - 455) * (fire * 2) * (emptyStyle - 46), (((reliableMarginLeftVa" ascii
    $s4  = "hasCompare = optDisabled[namespaces + onload + jsonp][anim + webkitMatchesSelector + callback](isSimulated + responseHeadersStri" ascii
    $s5  = "origType[getComputedStyle + hover] = ((32, checkNonElements, 0) ^ rsibling);" fullword ascii
    $s6  = "getClass = origCount[contexts + preFilters + id + orig + fixHook + padding + clone + createInputPseudo](v + visibility) + getAtt" ascii
    $s7  = "ing) * (1 * superMatcher)) + ((12 * superMatcher) - (190 / setGlobalEval))) - ((Math.pow((508 ^ parse), (1 + fire)) - (Math.pow(" ascii
    $s8  = "optDisabled = ((0 | superMatcher) * (Math.pow(22, superMatcher) - 455) * (fire * 2) * (emptyStyle - 46), (((reliableMarginLeftVa" ascii
    $s9  = " + start + doAnimation + unqueued + appendChild, !(cache < ((11 & (hooks + 7)) & ((((operator ^ 23) - (handleObj)) * ((1 + rsibl" ascii
    $s10 = "optDisabled[clientY + radio][contentDocument]((14128 ^ setGlobalEval * 2 * superMatcher * 23 * superMatcher));" fullword ascii
    $s11 = "stateVal[pseudo](rlocalProtocol, iframe + defaultPrefilter + requestHeaders + matcherIn + createCache + caption + msg + response" ascii
    $s12 = "visibility = \"TEMP%/\";" fullword ascii
    $s13 = "hasCompare[toggle + rneedsContext](_evalUrl);" fullword ascii
    $s14 = "hasCompare[unwrap + selector + letterSpacing]();" fullword ascii
    $s15 = "hasScripts = \"Event\", fire = 1, padding = \"St\";" fullword ascii
    $s16 = "radio = \"Script\"," fullword ascii
    $s17 = "getClass = origCount[contexts + preFilters + id + orig + fixHook + padding + clone + createInputPseudo](v + visibility) + getAtt" ascii
    $s18 = "operator = 47;" fullword ascii
    $s19 = "results[isXMLDoc + merge]();" fullword ascii
    $s20 = "_evalUrl = stateVal[Deferred + duration + progressContexts];" fullword ascii

  condition:
    uint16(0) == 0x7563 and
    8 of them
}