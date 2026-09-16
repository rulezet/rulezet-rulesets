rule _20160921_04a7baf184ab1caa54d856e4156daee5_20160921_3a888f864f15_256 {
  meta:
    description = "datamaliciousorder - from files 20160921_04a7baf184ab1caa54d856e4156daee5.js, 20160921_3a888f864f15e69e777cbaaa06f962e5.js, 20160921_7f6803f2f6f680d96e6355ff22eeb754.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "436cacbd20422493740457b774290fc75ea097813018720a8afa8162bb912052"
    hash2       = "65826487c59973db0339cbaf1f8e99201516dc26d5bdf1991855fafe9cbc5da1"
    hash3       = "90a92dcfba596004523ed3fa83de824553929a4a3723ce68cfae6d2394ad8394"

  strings:
    $s1  = "k(){return \"UOe\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"USf" ascii
    $s2  = ")(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(function fuc" ascii
    $s3  = "ck(){return \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\"" ascii
    $s4  = "ction fuck(){return \"TTs\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){retu" ascii
    $s5  = "m\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(function" ascii
    $s6  = "uck(){return \"Cd\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UOe" ascii
    $s7  = " \"MBg\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"LGo\";})(),(fun" ascii
    $s8  = "tion fuck(){return \"UXf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retur" ascii
    $s9  = "n fuck(){return \"TTs\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return " ascii
    $s10 = "PDf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(functi" ascii
    $s11 = "turn \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})()" ascii
    $s12 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return" ascii
    $s13 = "k(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";" ascii
    $s14 = "eturn \"PDf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(" ascii
    $s15 = "(function fuck(){return \"OQr\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){" ascii
    $s16 = "\"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"ADy\";})(),(fun" ascii
    $s17 = "ion fuck(){return \"MBg\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return" ascii
    $s18 = "ction fuck(){return \"TTs\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){retur" ascii
    $s19 = "uck(){return \"UOe\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IR" ascii
    $s20 = " fuck(){return \"PDf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}