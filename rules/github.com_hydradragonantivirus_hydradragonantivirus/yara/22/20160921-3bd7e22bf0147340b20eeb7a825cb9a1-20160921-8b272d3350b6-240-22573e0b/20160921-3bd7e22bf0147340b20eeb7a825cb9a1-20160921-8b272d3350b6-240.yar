rule _20160921_3bd7e22bf0147340b20eeb7a825cb9a1_20160921_8b272d3350b6_240 {
  meta:
    description = "datamaliciousorder - from files 20160921_3bd7e22bf0147340b20eeb7a825cb9a1.js, 20160921_8b272d3350b65135770a56abfe6a28e0.js, 20160921_aa7387335b72c30a3b2a33711bac8907.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fabcf64721727f8848bd26426a6a8b0fdf115e6416d2ce71dfa09efadb821690"
    hash2       = "e33679bc8447125e30a6b07d53b91fb8c7307bd0acbe67f2f89665270647873e"
    hash3       = "96ff6fd5b079de518bd1ded811f4e98bcf45211a849900012beeb7e498b7b721"

  strings:
    $s1  = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){retur" ascii
    $s2  = "ction fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){retur" ascii
    $s3  = "ck(){return \"Cd\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\"" ascii
    $s4  = "ction fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){retu" ascii
    $s5  = "(){return \"Za\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";}" ascii
    $s6  = "return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s7  = "(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"PDf\"" ascii
    $s8  = "ction fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){retur" ascii
    $s9  = " \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(fun" ascii
    $s10 = "\"MBg\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"ADy\";})(),(fun" ascii
    $s11 = "ck(){return \"Wo0\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn" ascii
    $s12 = "ck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn" ascii
    $s13 = ";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IRn\";})(),(function f" ascii
    $s14 = " fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"" ascii
    $s15 = "(function fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){" ascii
    $s16 = "\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(function " ascii
    $s17 = "\"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Cd\";})(),(funct" ascii
    $s18 = "\"GNm\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(funct" ascii
    $s19 = "return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(" ascii
    $s20 = "ion fuck(){return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}