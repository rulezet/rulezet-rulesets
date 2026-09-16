rule sig_20160308_8655ce1f7d676003a1a3d312b01ba3e6 {
  meta:
    description = "datamaliciousorder - file 20160308_8655ce1f7d676003a1a3d312b01ba3e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0336e512cee3eee5a9f853938bc3dd636280ceb7ac8b33687012a65aa871f0df"

  strings:
    $s1  = "ajaxSetup[filter + inspectPrefiltersOrTransports + linear + originAnchor](responseContainer, ((Math.pow(28, manipulationTarget) " ascii
    $s2  = "removeChild[optionSet](letter, focusin + border + escaped + delegate + delegateTarget + augmentWidthOrHeight + rsubmittable + _d" ascii
    $s3  = "em * ((19 * docElem + 3), (rsubmitterTypes / 41), (Math.pow(documentElement, 2) - parseJSON), (2 & manipulationTarget)), ((Math." ascii
    $s4  = "ajaxSetup = ct[ready + msg + string][rscriptType + has + rdisplayswap + contentType + pop](matchContext + css + string + postFin" ascii
    $s5  = "ajaxSetup = ct[ready + msg + string][rscriptType + has + rdisplayswap + contentType + pop](matchContext + css + string + postFin" ascii
    $s6  = "ajaxSetup[filter + inspectPrefiltersOrTransports + linear + originAnchor](responseContainer, ((Math.pow(28, manipulationTarget) " ascii
    $s7  = ") * (getBoundingClientRect - 35) * (binary / 50) ^ ((specialEasing & 1) * (hasFocus / 32)))) & ((((_jQuery ^ 253) / (toArray & 1" ascii
    $s8  = "isReady = ct[time + processData];" fullword ascii
    $s9  = "removeChild[queue + rkeyEvent]();" fullword ascii
    $s10 = "removeChild = ct[time + createInputPseudo + args][returnTrue + bubbleType + Data + whitespace](childNodes + temp + nonce + event" ascii
    $s11 = "removeChild = ct[time + createInputPseudo + args][returnTrue + bubbleType + Data + whitespace](childNodes + temp + nonce + event" ascii
    $s12 = "ct = ((13 & parentNode) * (246, removeClass, 23), (((origType + 3) * (specialEasing * 2) + manipulationTarget), this));" fullword ascii
    $s13 = "responseContainer = padding[merge + mappedTypes + el + elemData + version + wrap + dataAttr](stopOnFalse + not + matchAnyContext" ascii
    $s14 = "removeChild[optionSet](letter, focusin + border + escaped + delegate + delegateTarget + augmentWidthOrHeight + rsubmittable + _d" ascii
    $s15 = "body = \"o\", rkeyEvent = \"end\", Data = \"bje\", jsonp = \"te\";" fullword ascii
    $s16 = "html[progress](responseContainer.locked(), (specialEasing + -1), ((createTextNode | 0) | (specialEasing * 0)));" fullword ascii
    $s17 = "webkitMatchesSelector[stopped + queue + jsonProp] = (specialEasing + -(1 * specialEasing));" fullword ascii
    $s18 = "- 731) - (structure ^ 34)));" fullword ascii
    $s19 = "padding = isReady[clientY + jsonp + timeoutTimer + string](ready + charset + seed);" fullword ascii
    $s20 = "ct[show + overflowY + string][Deferred + originAnchor + file](((iframe & 15358) & (ajaxExtend / 19)));" fullword ascii

  condition:
    uint16(0) == 0x6c63 and
    8 of them
}