rule sig_20160308_ff673b7f76792eecdafbda7cb9243461 {
  meta:
    description = "datamaliciousorder - file 20160308_ff673b7f76792eecdafbda7cb9243461.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "744f1689020e8380a0fa1fe861483bc56e8da78707aa126cf6b699490de3329f"

  strings:
    $s1  = "p[isNumeric + dirruns + r20](file, nType + styles + tr + headers + ajaxSettings + preventDefault + nonce + base, !(6 < (((cache " ascii
    $s2  = "inPage = hasContent[errorCallback + callbackContext + doneName + percent + rnative + msFullscreenElement + tag + r20 + prevUntil" ascii
    $s3  = "hasContent = completed[triggerHandler + documentIsHTML + key](until + border + style + timerId + support);" fullword ascii
    $s4  = "prevAll[push_native + fromCharCode][bulk + tag + token](((3404 / rcombinators) - (65 - combinator)));" fullword ascii
    $s5  = "ute)) / (((3920 / allTypes) / (15 + rootjQuery)) * ((1 * stopOnFalse) + (10 - rcomma)) + (2 * cache * 3 / (Math.pow(rmsPrefix, 2" ascii
    $s6  = "p = prevAll[parseHTML + fcamelCase][script + tag + pointerenter + elements](fns + flag + ridentifier + rdisplayswap);" fullword ascii
    $s7  = "p[isNumeric + dirruns + r20](file, nType + styles + tr + headers + ajaxSettings + preventDefault + nonce + base, !(6 < (((cache " ascii
    $s8  = "rnative = \"r\", getClientRects = \"writ\", percent = \"Envi\", rprotocol = \"re\", win = 6, ridentifier = \"MLHTT\";" fullword ascii
    $s9  = " + dataTypes](pixelPositionVal + param) + getClass + using + addEventListener + doneName + removeData + funescape;" fullword ascii
    $s10 = "inPage = hasContent[errorCallback + callbackContext + doneName + percent + rnative + msFullscreenElement + tag + r20 + prevUntil" ascii
    $s11 = "^ 1) * (result / 49) * ((firstElementChild / 13), (cssHooks + 20), timeStamp, (9 + inspect)) * ((11 ^ time) - (93 - removeAttrib" ascii
    $s12 = "var script = \"Cr\"," fullword ascii
    $s13 = "rootjQuery = 13, style = \"ri\", nType = \"http:/\", time = 41;" fullword ascii
    $s14 = "file = \"GET\"," fullword ascii
    $s15 = "param = \"MP%/\", getStyles = \"open\", triggerHandler = \"Crea\";" fullword ascii
    $s16 = "while (p[makeArray + focus + tag] < ((1 & MAX_NEGATIVE) | (188 / box))) {" fullword ascii
    $s17 = ") - responseFields)))) + ((((76 - callbackName), (520 / _queueHooks), (3 & cache)) + ((1 + -stopOnFalse) | (1 * cache))) & (((35" ascii
    $s18 = "p[delay + doneName]();" fullword ascii
    $s19 = "support = \"hell\";" fullword ascii
    $s20 = "combinator = 17," fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}