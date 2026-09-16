rule sig_20160309_57cd77849a73456d7945ccdaf085dec1 {
  meta:
    description = "datamaliciousorder - file 20160309_57cd77849a73456d7945ccdaf085dec1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26f27969014081134dca1d7f0984c063bbb15c8c30aa536ad5727648dcfb8a3d"

  strings:
    $x1  = "optDisabled[stopped](boxSizingReliable + notifyWith, removeEventListener + callbackExpect + show + params + params + nodeNameSel" ascii
    $s2  = "| 1))) + ((onlyHandlers * 0) / (marginRight ^ 21)))) - ((Math.pow(((cors ^ 152) | (xhr / 5)), ((forward / 25) / (image ^ 13))) -" ascii
    $s3  = "optDisabled = startLength[apply + hooks + isSimulated + pixelMarginRightVal][target + setMatcher + converters](prevUntil + defau" ascii
    $s4  = "optDisabled = startLength[apply + hooks + isSimulated + pixelMarginRightVal][target + setMatcher + converters](prevUntil + defau" ascii
    $s5  = " ((username * 9 + curPosition) ^ (13433 ^ ready))) / ((127 & (timeoutTimer + 36)), ((JSON / 1) - (firstDataType / 26)), ((opt & " ascii
    $s6  = "aultValue + addClass, !((Math.pow(((26 - timer) + (1 & onlyHandlers)) * ((5 * restoreScript, 3)), (((when) + (1 + -(overwritten " ascii
    $s7  = "255), (dataAttr | 6), (match + 108), (Math.pow(nativeStatusText, 2) - result)), ((1 ^ when) + (146, jsonProp, 1))))) > letter));" ascii
    $s8  = "hidden[script + optgroup]();" fullword ascii
    $s9  = " target = \"Cr\"," fullword ascii
    $s10 = "startLength = ((6 ^ wrapMap), (((2160 / hasData) / (13 - v)), this));" fullword ascii
    $s11 = "rsubmittable[handlers + offsetHeight] = ((overwritten / 39) | (dispatch - 38));" fullword ascii
    $s12 = "rpseudo = view[completed + rinputs + original + innerHTML + contains](old + origCount + prevAll);" fullword ascii
    $s13 = "optDisabled[token + stateVal]();" fullword ascii
    $s14 = "hidden[tabIndex + notifyWith + parsed + lastModified + responseFields](next, ((speed + 47) / (j / 9)));" fullword ascii
    $s15 = "hidden = startLength[old + startTime][compile + acceptData + converters](computed + andSelf + isSuccess + nodeNameSelector);" fullword ascii
    $s16 = "startLength[toSelector + focus][cloneCopyEvent + querySelectorAll](((Math.pow(lang, 2) - outerCache) ^ (13388 & checkNonElements" ascii
    $s17 = "startLength[toSelector + focus][cloneCopyEvent + querySelectorAll](((Math.pow(lang, 2) - outerCache) ^ (13388 & checkNonElements" ascii
    $s18 = " script = \"ope\";" fullword ascii
    $s19 = "restoreScript = 11, defaultPrefilter = \"L2.\", when = 2;" fullword ascii
    $s20 = "forward = 550;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}