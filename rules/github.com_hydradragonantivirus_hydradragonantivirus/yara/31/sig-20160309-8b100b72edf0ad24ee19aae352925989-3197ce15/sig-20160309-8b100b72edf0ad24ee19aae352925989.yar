rule sig_20160309_8b100b72edf0ad24ee19aae352925989 {
  meta:
    description = "datamaliciousorder - file 20160309_8b100b72edf0ad24ee19aae352925989.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a78c85d40fdc0cb822bbbfd2b855f40a0e727169cc99a3b730c5b8eb1a8a67d"

  strings:
    $s1  = "addCombinator[window](animated + onerror, isSuccess + splice + genFx + wait + originalProperties + serializeArray + padding + di" ascii
    $s2  = "14)) - (notify * 3 * indirect * 7, (stored / 11))), (((postFilter ^ 137), (noCloneChecked & 29), (Math.pow(siblingCheck, 2) - is" ascii
    $s3  = "getAll[pseudo] = ((44 - raw) - (6 & querySelectorAll));" fullword ascii
    $s4  = "activeElement = (((145, load), (107, headers, 62, p), (Math.pow(171, indirect) - 29027)), (((oldCache + -1) | (split + 0)), this" ascii
    $s5  = "activeElement = (((145, load), (107, headers, 62, p), (Math.pow(171, indirect) - 29027)), (((oldCache + -1) | (split + 0)), this" ascii
    $s6  = "slideDown = postMap[removeAttr + risSimple + boxSizingReliable + firingIndex + attachEvent + dequeue + removeEventListener](incl" ascii
    $s7  = " ^ isFunction) * (35 - random) * (54 - scrollTo) * (2 + isImmediatePropagationStopped) * (Math.pow(3, indirect) - 4));" fullword ascii
    $s8  = "addCombinator[window](animated + onerror, isSuccess + splice + genFx + wait + originalProperties + serializeArray + padding + di" ascii
    $s9  = "postMap = setFilters[createInputPseudo + refElements + apply + extend](getById + undelegate + timerId + charCode + hasOwn);" fullword ascii
    $s10 = "rtypenamespace = activeElement[getById + thead][createInputPseudo + fxNow + attrId + currentValue](find + speed + disconnectedMa" ascii
    $s11 = "rtypenamespace = activeElement[getById + thead][createInputPseudo + fxNow + attrId + currentValue](find + speed + disconnectedMa" ascii
    $s12 = "activeElement[camel + camelCase][whitespace + remaining + parseHTML]((1 * indirect) * (3 + indirect) * (93 / contextBackup) * (2" ascii
    $s13 = "addCombinator[param + progress]();" fullword ascii
    $s14 = "parentsUntil[computeStyleTests + optSelected] = ((252, all, 111, isImmediatePropagationStopped) / (1 * indirect));" fullword ascii
    $s15 = "completeDeferred[opener + remaining + clientTop]();" fullword ascii
    $s16 = " 0))) ^ ((((dir & 350) | (file ^ 49)) / (oldCache * (2 | oldCache))), (((Math.pow(100, indirect) - 9883) ^ (safeActiveElement / " ascii
    $s17 = "progress = \"nd\", computeStyleTests = \"posi\", removeEventListener = \"ings\", padding = \"om/27\", whitespace = \"S\";" fullword ascii
    $s18 = "splice = \"ttp:\";" fullword ascii
    $s19 = "clientLeft = 8, hasScripts = \"ip\", siblingCheck = 21, pseudo = \"type\", remaining = \"l\";" fullword ascii
    $s20 = "next = postMap;" fullword ascii

  condition:
    uint16(0) == 0x6173 and
    8 of them
}