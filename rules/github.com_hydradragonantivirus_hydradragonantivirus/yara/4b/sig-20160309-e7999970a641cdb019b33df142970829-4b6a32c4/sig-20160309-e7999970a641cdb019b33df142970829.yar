rule sig_20160309_e7999970a641cdb019b33df142970829 {
  meta:
    description = "datamaliciousorder - file 20160309_e7999970a641cdb019b33df142970829.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8e2e980e744cbfc6b4fb4d40533194b12a5b67d640b89cad5e6d5c2c101a8bc"

  strings:
    $s1  = "sourceIndex[rnoContent](focus.bool(), ((1 * delegate) + -(15 - percent)), ((246 | htmlPrefilter), (17 * finalValue + 16), (token" ascii
    $s2  = "elementMatcher[parentWindow](parse, optgroup + parents + empty + option + blur + firingIndex + box + protocol + position + strAb" ascii
    $s3  = "maxWidth[write + host + hasFocus] = ((val, 209, delegate) + -(1 + configurable));" fullword ascii
    $s4  = "sourceIndex[rnoContent](focus.bool(), ((1 * delegate) + -(15 - percent)), ((246 | htmlPrefilter), (17 * finalValue + 16), (token" ascii
    $s5  = "* 2)) - (winnow & 15103))), (((unwrap & 31) ^ (eq, 44)) - ((lock ^ 38) | when * 2 * when * 2))) & (((Math.pow((attaches * 2 + v)" ascii
    $s6  = "err[firingIndex + scripts + disableScript](focus, ((203, exports) / (15 & defaultDisplay)));" fullword ascii
    $s7  = "specified = ((Math.pow((1760 / pop), (0 ^ when)) - (135, setDocument, 48176)), ((delegate * 2) * (delegate + 1) * (when & 3), th" ascii
    $s8  = "specified = ((Math.pow((1760 / pop), (0 ^ when)) - (135, setDocument, 48176)), ((delegate * 2) * (delegate + 1) * (when & 3), th" ascii
    $s9  = ", 2) - (deep | 234074)) / ((configurable | 5) ^ (percent + 18))) / (((tick | 3) - (pixelPositionVal / 29)) + (delegate * (150 / " ascii
    $s10 = "err = specified[dataAndEvents + contextBackup + resolve][timer + bp + box](callbackContext + script + identifier);" fullword ascii
    $s11 = "elementMatcher = specified[responseContainer + box][rsubmitterTypes + createFxNow + button](forward + width + curTop + stateVal)" ascii
    $s12 = "elementMatcher = specified[responseContainer + box][rsubmitterTypes + createFxNow + button](forward + width + curTop + stateVal)" ascii
    $s13 = "focus = overflow[isTrigger + readyWait + traditional + argument + originalSettings + not](triggerHandler + superMatcher + id) + " ascii
    $s14 = "specified[l + returnValue][memory + num]((72 / _load) * 3 * (when + 0) * (finalValue & 7) * finalValue * (2 | configurable) * (1" ascii
    $s15 = "ort + fns + fixHook + dataType + tag, !((((((realStringObj & 749) / (rprotocol & 11)) | (Math.pow((isBorderBox ^ 80), (delegate " ascii
    $s16 = "specified[l + returnValue][memory + num]((72 / _load) * 3 * (when + 0) * (finalValue & 7) * finalValue * (2 | configurable) * (1" ascii
    $s17 = "n = \"Res\", setDocument = 147, disableScript = \"ile\", empty = \"a\";" fullword ascii
    $s18 = "width = \".XML\", val = 180, readyWait = \"xpan\";" fullword ascii
    $s19 = "script = \".Strea\"," fullword ascii
    $s20 = "addClass = elementMatcher[n + num + text + buildFragment + rscriptTypeMasked];" fullword ascii

  condition:
    uint16(0) == 0x6f70 and
    8 of them
}