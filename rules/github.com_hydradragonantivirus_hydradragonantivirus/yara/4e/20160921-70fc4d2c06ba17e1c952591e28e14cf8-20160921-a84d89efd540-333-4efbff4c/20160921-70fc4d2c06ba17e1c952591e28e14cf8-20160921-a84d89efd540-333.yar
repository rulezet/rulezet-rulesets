rule _20160921_70fc4d2c06ba17e1c952591e28e14cf8_20160921_a84d89efd540_333 {
  meta:
    description = "datamaliciousorder - from files 20160921_70fc4d2c06ba17e1c952591e28e14cf8.js, 20160921_a84d89efd5400c906c1132a56b0ef679.js, 20160921_f42ed060a223d31bf315f08c4c668579.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "439af0812c2462e15038b6b3de132befd472f89a6810bf0f930acba54e4873ad"
    hash2       = "f3cfecdabdf17d9af410d0fee7ec88844bc361668aca1a114832bd3e515d3456"
    hash3       = "e1af3f6144c617b4734d9d1f2ae999f7e6d3a46f08760085978213f7cbc38bce"

  strings:
    $s1  = "fuck(){return \"Hs\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii
    $s2  = "urn \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(" ascii
    $s3  = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck()" ascii
    $s4  = "(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){r" ascii
    $s5  = "fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"M" ascii
    $s6  = "n \"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Vb\";})(),(fu" ascii
    $s7  = "tion fuck(){return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return" ascii
    $s8  = "Os\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"YQt\";})(),(functi" ascii
    $s9  = "uck(){return \"Np\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\"" ascii
    $s10 = "Sf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Cd\";})(),(function" ascii
    $s11 = "eturn \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Wo0\";})(" ascii
    $s12 = "urn \"Dc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Zy\";})(),(f" ascii
    $s13 = "(){return \"GNm\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\"" ascii
    $s14 = "ion fuck(){return \"GNm\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return" ascii
    $s15 = "tion fuck(){return \"PDf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){retur" ascii
    $s16 = "\"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(func" ascii
    $s17 = "nction fuck(){return \"Cd\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retu" ascii
    $s18 = "n \"OQr\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Za\";})(),(fun" ascii
    $s19 = "{return \"PDf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})" ascii
    $s20 = "fuck(){return \"CTm\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"GWo" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}