rule sig_20160311_233a1aa3cca58f31d31203c8ae2ae659 {
  meta:
    description = "datamaliciousorder - file 20160311_233a1aa3cca58f31d31203c8ae2ae659.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd06e93052754326e2f1ac907c22122a1b8987cc40f423cb37815974507dacd8"

  strings:
    $x1  = "refElements[\"o\" + origType + \"e\" + rtrim](\"G\".code() + writable, \"http:\" + wrapMap + \"o.go\" + evt + \"23r35\".code() +" ascii
    $s2  = ", !(tokens < (((((408 & ridentifier) - (3 * hidden + 1)), ((defaultPrefilter + 10746))) / (((i / 20) | (Math.pow(qualifier, 2) -" ascii
    $s3  = "ready = (((15 & cur) * (2 * tokens + 1) + (focus - 28)), ((matchExpr | 0) & (t | 0)), eval(\"t\" + checked + \"i\".code() + appe" ascii
    $s4  = "ready = (((15 & cur) * (2 * tokens + 1) + (focus - 28)), ((matchExpr | 0) & (t | 0)), eval(\"t\" + checked + \"i\".code() + appe" ascii
    $s5  = "preFilter[compile + \"eToFil\" + pixelMarginRightVal](height, ((Math.pow(rpseudo, 2) - delegateType), (2 & curCSSLeft)));" fullword ascii
    $s6  = "refElements[\"o\" + origType + \"e\" + rtrim](\"G\".code() + writable, \"http:\" + wrapMap + \"o.go\" + evt + \"23r35\".code() +" ascii
    $s7  = "v)) | (((12 - rheaders) + (50 & replaceAll)) & (53, nonce, 40, reverse) * (8 / getElementById))))));" fullword ascii
    $s8  = "preFilter = ready[\"WScrip\".code() + module][\"Create\" + rnotwhite](\"ADOD\" + s + \"am\".code());" fullword ascii
    $s9  = "handleObj = ready[\"WScri\" + sort];" fullword ascii
    $s10 = "letter = \"ty\", i = 3460, parentOffset = 20, nonce = 151, scripts = \"/\", pixelMarginRightVal = \"e\";" fullword ascii
    $s11 = "height = oldCache[disabled + \"Envir\" + tick + \"tSt\".code() + toggleClass + \"s\"](parentWindow + \"MP%\" + scripts) + \"_def" ascii
    $s12 = "height = oldCache[disabled + \"Envir\" + tick + \"tSt\".code() + toggleClass + \"s\"](parentWindow + \"MP%\" + scripts) + \"_def" ascii
    $s13 = "var hidden = 23;" fullword ascii
    $s14 = "add[letter + \"p\" + pixelMarginRightVal] = (1 * (matchExpr & 1));" fullword ascii
    $s15 = "refElements[append + \"e\" + implicitRelative]();" fullword ascii
    $s16 = "+ optSelected + \"t\" + high + \"cr\";" fullword ascii
    $s17 = "preFilter[beforeSend + \"en\"]();" fullword ascii
    $s18 = "compile = \"sav\";" fullword ascii
    $s19 = "refElements = ready[close + \"ript\".code()][properties + \"ateObj\" + PI](\"MSXML2\" + jsonpCallback + \"LHT\".code() + image);" ascii
    $s20 = "close = \"WSc\";" fullword ascii

  condition:
    uint16(0) == 0x7270 and
    1 of ($x*) and 4 of them
}