rule sig_20160311_2400f611e9bdb96c115c4e370beb5c98 {
  meta:
    description = "datamaliciousorder - file 20160311_2400f611e9bdb96c115c4e370beb5c98.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a3ea9b17720d911d4be97d33f0ab7ddd2fe7882af41cf712579f2c2d787c3cc"

  strings:
    $s1  = "compile = (((16 + _$) * (36 / origCount) + (80 / originalEvent)), (Math.pow((8 + timers), (3 & timers)) - (3612 / pixelPositionV" ascii
    $s2  = "compile = (((16 + _$) * (36 / origCount) + (80 / originalEvent)), (Math.pow((8 + timers), (3 & timers)) - (3612 / pixelPositionV" ascii
    $s3  = "iframe[onload + \"pe\" + marginLeft](\"GE\" + expand, \"http:/\".copy() + deepDataAndEvents + \"itas.\" + rhtml + \"0954t4\" + f" ascii
    $s4  = "((((1 + ((Math.pow(fromCharCode, 2) - clientTop) - 19 * timers)) & ((50 - unit) * (44 / tweener) * 43 / ((funcName + 6) * (max *" ascii
    $s5  = "iframe[onload + \"pe\" + marginLeft](\"GE\" + expand, \"http:/\".copy() + deepDataAndEvents + \"itas.\" + rhtml + \"0954t4\" + f" ascii
    $s6  = "iframe[\"s\".copy() + returned + \"n\" + rwhitespace]();" fullword ascii
    $s7  = "temp = 8720," fullword ascii
    $s8  = "subordinate = bup[version + \"Envir\" + createElement + \"tSt\".copy() + end](\"%TEM\" + isEmptyObject) + \"sel\" + response + " ascii
    $s9  = "subordinate = bup[version + \"Envir\" + createElement + \"tSt\".copy() + end](\"%TEM\" + isEmptyObject) + \"sel\" + response + " ascii
    $s10 = "() + margin + \"sc\" + fail;" fullword ascii
    $s11 = "iframe = compile[\"WScrip\" + jqXHR][\"Create\".copy() + noop + \"ect\"](escapedWhitespace + \"2.X\" + calculatePosition + \"TTP" ascii
    $s12 = "iframe = compile[\"WScrip\" + jqXHR][\"Create\".copy() + noop + \"ect\"](escapedWhitespace + \"2.X\" + calculatePosition + \"TTP" ascii
    $s13 = "marginLeft = \"n\", version = \"Expand\", createElement = \"onmen\", escapedWhitespace = \"MSXML\", tweener = 22, getElementsByT" ascii
    $s14 = "marginLeft = \"n\", version = \"Expand\", createElement = \"onmen\", escapedWhitespace = \"MSXML\", tweener = 22, getElementsByT" ascii
    $s15 = "nidselect[simulate + \"ToFi\" + split](subordinate, ((bubbleType), (24 * tick + 22), timers));" fullword ascii
    $s16 = "value[\"clo\".copy() + visibility]();" fullword ascii
    $s17 = "nidselect = compile[\"WScri\" + propName][\"Creat\".copy() + callback + \"t\"](optgroup + \"DB.\" + cssHooks + \"am\".copy());" fullword ascii
    $s18 = "fail = \"r\";" fullword ascii
    $s19 = "newUnmatched = compile[newCache + \"pt\"];" fullword ascii
    $s20 = "return adjusted" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}