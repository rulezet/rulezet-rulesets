rule sig_20160309_083f5f9df9c3e6485499a7624925a64c {
  meta:
    description = "datamaliciousorder - file 20160309_083f5f9df9c3e6485499a7624925a64c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1251066dfe34f839710f25b081cc4393b8d9313dae8d48ff453361b5ad4594cb"

  strings:
    $s1  = "contentDocument[rclickable + resolveContexts](isWindow + refElements, rbracket + charCode + elementMatchers + parts + select + e" ascii
    $s2  = "xtend + compareDocumentPosition, !((((((3600 / test) & (2852 / hasScripts)) & (2 * isArray + (Math.pow(55, focusin) - 2923))) - " ascii
    $s3  = "rigFn + (50 / domManip))) | (((283 + curCSSTop) / (Math.pow(20, focusin) - 377)) & ((MAX_NEGATIVE * 3 + access) / (40 - forward)" ascii
    $s4  = "lock = camelCase[parsed + checkDisplay + onerror + rrun + closest](overflow + createComment + pixelPosition + getClientRects);" fullword ascii
    $s5  = "pixelMarginRightVal = value[curCSS + fnOut + accepts + cleanData + createComment][write + stopOnFalse + tuple + replaceAll + clo" ascii
    $s6  = "sest](empty + dataAttr + getComputedStyle + disconnectedMatch);" fullword ascii
    $s7  = "handleObj[locked](tuples.bup(), ((1 * timer) + -1), (param));" fullword ascii
    $s8  = "value = ((Math.pow((144 + serialize), (32 - test)) - (112, add, 123, rmultiDash)), (((6 + focusin) | (0 / documentElement)), thi" ascii
    $s9  = "prevAll = \"%TEMP%\", lname = 10, stopOnFalse = \"re\", handleObjIn = \"wri\", reverse = \"S\";" fullword ascii
    $s10 = "contentDocument = value[createInputPseudo + ignored + createComment][classCache + runescape + resolveValues + rsibling](notify +" ascii
    $s11 = "value = ((Math.pow((144 + serialize), (32 - test)) - (112, add, 123, rmultiDash)), (((6 + focusin) | (0 / documentElement)), thi" ascii
    $s12 = "contentDocument = value[createInputPseudo + ignored + createComment][classCache + runescape + resolveValues + rsibling](notify +" ascii
    $s13 = "contentDocument[rclickable + resolveContexts](isWindow + refElements, rbracket + charCode + elementMatchers + parts + select + e" ascii
    $s14 = "getWindow[elemLang + suffix + mouseHooks] = param;" fullword ascii
    $s15 = "(((test - 11) + (success / 33)) & isArray * 3 * (returned / 34))) - ((((lname * 8 + rxhtmlTag) / (256 / actualDisplay)) ^ (5 * o" ascii
    $s16 = "pixelMarginRightVal = value[curCSS + fnOut + accepts + cleanData + createComment][write + stopOnFalse + tuple + replaceAll + clo" ascii
    $s17 = "forward = 27;" fullword ascii
    $s18 = "getWindow = hide;" fullword ascii
    $s19 = "onSet + checkDisplay + pageYOffset + optgroup + accepts;" fullword ascii
    $s20 = "isWindow = (function String.prototype.bup() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}