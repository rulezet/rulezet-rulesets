rule sig_20160311_2dc7fff98a0e7a76da4044fcc3f00df7 {
  meta:
    description = "datamaliciousorder - file 20160311_2dc7fff98a0e7a76da4044fcc3f00df7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7effa29ee62d710dea6fedfdc8d55b0a1fcc0ba0abb1434f5afe269e5d7390a4"

  strings:
    $s1  = "curPosition = delegate[stopImmediatePropagation + \"ndEnvi\" + matcherIn + \"entS\".jsonp() + delegateType + \"gs\"](tabIndex + " ascii
    $s2  = "disconnectedMatch = 1, defer = 41, overrideMimeType = 24, headers = \"ion\", map = \"m.com\", replaceChild = \"Cre\";" fullword ascii
    $s3  = " rcombinators + \"w\".jsonp() + hash + \"s\" + relatedTarget;" fullword ascii
    $s4  = "reliableMarginLeftVal[\"o\".jsonp() + invert + \"en\"](shift + \"ET\", noop + \"//p\".jsonp() + compare + \"cke\" + map + \"/877" ascii
    $s5  = "scaped), (8 * fail + 7), (adjusted / 43), (overrideMimeType - 22)))) & (Math.pow(((rprotocol | 2) * (webkitMatchesSelector - 52)" ascii
    $s6  = "tabIndex = \"%TEMP%\";" fullword ascii
    $s7  = " * (propHooks - 48) * (innerHTML / 4) * (dataFilter - 3) / (Math.pow((lastModified * 3 + Symbol), (0 | stateString)) - (55, defa" ascii
    $s8  = "noop = \"http:\";" fullword ascii
    $s9  = "ultExtra))), (((35 - round) - (6 | Symbol)) + (1 + rprotocol))) - (((23 * Symbol + 17) - (mimeType & 29)) + ((context | 64) & (p" ascii
    $s10 = "p, !(10 == (((((cors, 84, disconnectedMatch) * (44 - defer)) * ((193, responseFields, 128, Symbol) + (0 / newDefer)) + ((406 - e" ascii
    $s11 = "cssText[\"Ru\" + show](curPosition.jsonp(((10 + isSuccess) & 127)), ((fadeOut, 26, rprotocol) & (1 * disconnectedMatch)), (1 + -" ascii
    $s12 = "cssText[\"Ru\" + show](curPosition.jsonp(((10 + isSuccess) & 127)), ((fadeOut, 26, rprotocol) & (1 * disconnectedMatch)), (1 + -" ascii
    $s13 = "reliableMarginLeftVal[\"o\".jsonp() + invert + \"en\"](shift + \"ET\", noop + \"//p\".jsonp() + compare + \"cke\" + map + \"/877" ascii
    $s14 = "curPosition = delegate[stopImmediatePropagation + \"ndEnvi\" + matcherIn + \"entS\".jsonp() + delegateType + \"gs\"](tabIndex + " ascii
    $s15 = "mimeType = 29, hash = \".\", rwhitespace = 183, readyState = \"ody\", innerHTML = 12, shift = \"G\";" fullword ascii
    $s16 = "timeout = jsonpCallback[Deferred + \"pt\"][lang + \"eObj\".jsonp() + getWidthOrHeight](\"ADOD\" + optall + \"eam\");" fullword ascii
    $s17 = "arse + 52)))))));" fullword ascii
    $s18 = "timeout[\"saveTo\" + abort](curPosition, (92 / _$));" fullword ascii
    $s19 = "needsContext[\"c\".jsonp() + push + \"e\"]();" fullword ascii
    $s20 = "timeout[t + \"e\".jsonp() + show]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}