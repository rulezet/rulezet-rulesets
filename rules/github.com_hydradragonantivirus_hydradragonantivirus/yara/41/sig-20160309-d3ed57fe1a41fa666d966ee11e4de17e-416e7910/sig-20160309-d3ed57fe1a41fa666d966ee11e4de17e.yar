rule sig_20160309_d3ed57fe1a41fa666d966ee11e4de17e {
  meta:
    description = "datamaliciousorder - file 20160309_d3ed57fe1a41fa666d966ee11e4de17e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d9039becbe2e6f29c6f6d5cd751b355061294b92a0e6dd5747e34d38f3e57bf"

  strings:
    $s1  = "replaceAll[scrollTop](curOffset + version, disableScript + specialEasing + progress + source + createInputPseudo + count + rclas" ascii
    $s2  = "related = support[overflowX + overwritten + defaultExtra](define + prependTo + owner + getBoundingClientRect + completed);" fullword ascii
    $s3  = "replaceAll[scrollTop](curOffset + version, disableScript + specialEasing + progress + source + createInputPseudo + count + rclas" ascii
    $s4  = "rcleanScript[constructor + documentIsHTML]();" fullword ascii
    $s5  = "pattern = related[mouseleave + requestHeadersNames + subordinate + rnamespace + options + groups + nid + step](pixelPositionVal " ascii
    $s6  = "replaceAll = ajaxSettings[disable + rreturn][allTypes + elementMatcher + returnFalse + rquickExpr](nonce + operator + indirect +" ascii
    $s7  = "pattern = related[mouseleave + requestHeadersNames + subordinate + rnamespace + options + groups + nid + step](pixelPositionVal " ascii
    $s8  = "replaceAll = ajaxSettings[disable + rreturn][allTypes + elementMatcher + returnFalse + rquickExpr](nonce + operator + indirect +" ascii
    $s9  = "cent), (10 + speed)) - ((1 & doAnimation) ^ (6 | doAnimation))))) > 8));" fullword ascii
    $s10 = "mLang, 2) - prefix))) * ((1666 / wrapAll) - 46) & (((doAnimation ^ 11) | marginDiv * (99, andSelf, 236, unmatched)) & (((3 + per" ascii
    $s11 = "collection[removeEvent](pattern.prefilterOrFactory(), (1 + -(deep / 48)), (len - 45));" fullword ascii
    $s12 = "support = ajaxSettings[focus + defaultExtra];" fullword ascii
    $s13 = "s + udataOld + risSimple + rbuggyMatches, !((((unmatched * 2 * params) / (2 * radio * 2 * radio * 2 * params * 2 / (Math.pow(ele" ascii
    $s14 = "animation = replaceAll[keyHooks + dataTypeExpression + cssHooks + seekingTransport];" fullword ascii
    $s15 = "operator = \".X\";" fullword ascii
    $s16 = "params = 23, getBoundingClientRect = \"She\", original = \"pen\";" fullword ascii
    $s17 = "timeoutTimer[after + fadeOut] = (110, size, 91, doAnimation);" fullword ascii
    $s18 = "+ clientX + origType) + parentOffset + matcherFromGroupMatchers + option + click;" fullword ascii
    $s19 = "tuple[newDefer + defaultExtra + documentIsHTML](animation);" fullword ascii
    $s20 = "ajaxSettings[define + removeAttr][appendTo + empty + ontype](((335 + reliableMarginLeftVal) + (5641 ^ top)));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}