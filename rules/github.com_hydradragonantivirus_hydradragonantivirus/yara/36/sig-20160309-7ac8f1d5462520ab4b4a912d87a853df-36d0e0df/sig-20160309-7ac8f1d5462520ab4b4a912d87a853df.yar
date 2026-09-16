rule sig_20160309_7ac8f1d5462520ab4b4a912d87a853df {
  meta:
    description = "datamaliciousorder - file 20160309_7ac8f1d5462520ab4b4a912d87a853df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90e4468b681b4dfcac724aa46904e8fdadbf8cd238b88d9e2769c1f2024d078d"

  strings:
    $s1  = "filter[charCode](triggerHandler + easing, contextBackup + merge + readyState + hide + col + resolveValues + serializeArray, !(((" ascii
    $s2  = "keyHooks[getClientRects + onlyHandlers + nodeType][vendorPropName + wait]((Math.pow((one & 13441), postMap) - (13332294 ^ result" ascii
    $s3  = "keyHooks[getClientRects + onlyHandlers + nodeType][vendorPropName + wait]((Math.pow((one & 13441), postMap) - (13332294 ^ result" ascii
    $s4  = "elemLang = keyHooks[getClientRects + getStyles + owner][handleObj + root + owner](match + optDisabled + rbuggyQSA + end + parent" ascii
    $s5  = "elemLang = keyHooks[getClientRects + getStyles + owner][handleObj + root + owner](match + optDisabled + rbuggyQSA + end + parent" ascii
    $s6  = "memory = \"W\", postMap = 2, hash = \"seBody\", getScript = \"Expan\", rmouseEvent = \"si\";" fullword ascii
    $s7  = "tMap * 2 * postMap * 11) & ((err - 192) - (status ^ 1))), ((swing + 0) + -(noop / 49)), (((swing & 1) + (postMap + 3)) + dataUse" ascii
    $s8  = "elemLang[b + remove + matcher](setGlobalEval, ((15 - swing) - (5 * postMap + 2)));" fullword ascii
    $s9  = "name[register](setGlobalEval.clearQueue(), ((114, dataType, 231, pageYOffset) - (1 | pageYOffset)), ((0 & swing) / 2 * postMap *" ascii
    $s10 = "name[register](setGlobalEval.clearQueue(), ((114, dataType, 231, pageYOffset) - (1 | pageYOffset)), ((0 & swing) / 2 * postMap *" ascii
    $s11 = "filter = keyHooks[overrideMimeType + nodeType][push_native + marginRight + owner](activeElement + nativeStatusText + high + onty" ascii
    $s12 = "setGlobalEval = t[getScript + preexisting + fnOver + callbackName + parse + events + createHTMLDocument](scripts + classes) + in" ascii
    $s13 = "((1 & swing) ^ ((1 * inspectPrefiltersOrTransports) ^ (0 & swing))) & (((1 ^ inspectPrefiltersOrTransports) + -(1 & swing)) ^ ((" ascii
    $s14 = "setGlobalEval = t[getScript + preexisting + fnOver + callbackName + parse + events + createHTMLDocument](scripts + classes) + in" ascii
    $s15 = "keyHooks = (((14 * time + 2)), (((toArray ^ 184), (charset * 2 + dataUser)), this));" fullword ascii
    $s16 = "1 + -swing) ^ (1 + -swing)))) | ((((0 ^ offsetWidth) | (45 & multipleContexts)) | ((1 * special) * 2 + (structure | 12))), ((pos" ascii
    $s17 = "filter = keyHooks[overrideMimeType + nodeType][push_native + marginRight + owner](activeElement + nativeStatusText + high + onty" ascii
    $s18 = "ajaxHandleResponses = keyHooks[memory + risSimple + matcherOut];" fullword ascii
    $s19 = "filter[charCode](triggerHandler + easing, contextBackup + merge + readyState + hide + col + resolveValues + serializeArray, !(((" ascii
    $s20 = "file = filter[eventDoc + prevUntil + teardown + hash];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}