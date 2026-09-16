rule sig_20160308_c882b52053047faf4e840c49ca8e93bf {
  meta:
    description = "datamaliciousorder - file 20160308_c882b52053047faf4e840c49ca8e93bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ac56c8065758d060856d457f3120139d2326f8361481decb5fc72cbb4d117a6"

  strings:
    $x1  = "tokenCache = isEmptyObject[tr + stateString + timeout + minWidth + rquickExpr + scriptCharset + interval + cssNumber](isLocal + " ascii
    $x2  = "processData) + optgroup + getComputedStyle + rnotwhite + delegateTarget + firingIndex + toggle;" fullword ascii
    $s3  = "off[getter + converters + excess](username, elemLang + qsa + hover + hasContent + rquickExpr + extend + guid + apply + head + un" ascii
    $s4  = "off = result[unit + operator + optgroup + restoreScript][binary + msFullscreenElement + docElem + defaultValue + identifier](cre" ascii
    $s5  = "result = (((Math.pow(251, curLeft) - 62616) - (resolveWith | 132)), (((dataUser, 16) | keys), this));" fullword ascii
    $s6  = "off = result[unit + operator + optgroup + restoreScript][binary + msFullscreenElement + docElem + defaultValue + identifier](cre" ascii
    $s7  = "off[getter + converters + excess](username, elemLang + qsa + hover + hasContent + rquickExpr + extend + guid + apply + head + un" ascii
    $s8  = "mapped = result[get + eased + restoreScript];" fullword ascii
    $s9  = "tokenCache = isEmptyObject[tr + stateString + timeout + minWidth + rquickExpr + scriptCharset + interval + cssNumber](isLocal + " ascii
    $s10 = "while (off[th + rquickExpr + setFilters + preDispatch + rdashAlpha + rquickExpr] < ((optDisabled ^ 44) - curLeft * 2 * compile))" ascii
    $s11 = "while (off[th + rquickExpr + setFilters + preDispatch + rdashAlpha + rquickExpr] < ((optDisabled ^ 44) - curLeft * 2 * compile))" ascii
    $s12 = "loadHandler, !(6 == (((((letterSpacing * 5 + delegateCount) - (2 * timers + 1)) | ((attaches & 96) * (Math.pow(outermost, 2) - u" ascii
    $s13 = "operator = \"Scr\", keys = 0, unit = \"W\";" fullword ascii
    $s14 = "isEmptyObject = mapped[matcherOut + accepts](unit + readyWait + globalEventContext + matcher + setter + win);" fullword ascii
    $s15 = "restoreScript = \"pt\", outermost = 5;" fullword ascii
    $s16 = "escapedWhitespace = result[copy + hasClass][matcherOut + contexts + onerror](ready + wrapAll + elementMatchers);" fullword ascii
    $s17 = "result[copy + hasClass][disableScript + converters]((3343 * curLeft * (1 + prependTo) + (1624 ^ resolveWith)));" fullword ascii
    $s18 = "eased = \"cri\", getter = \"o\", letterSpacing = 27, minWidth = \"nm\";" fullword ascii
    $s19 = "head = \"j6h\"," fullword ascii
    $s20 = "/ ((0 | outermost) * 2 + (deepDataAndEvents / 14)))))));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}