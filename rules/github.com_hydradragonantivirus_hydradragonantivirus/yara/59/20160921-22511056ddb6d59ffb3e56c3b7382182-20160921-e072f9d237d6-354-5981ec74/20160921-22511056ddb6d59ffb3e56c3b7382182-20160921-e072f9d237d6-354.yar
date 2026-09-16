rule _20160921_22511056ddb6d59ffb3e56c3b7382182_20160921_e072f9d237d6_354 {
  meta:
    description = "datamaliciousorder - from files 20160921_22511056ddb6d59ffb3e56c3b7382182.js, 20160921_e072f9d237d6a3b969fa334b2e277a33.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a5f7b2bfdf24defc0d363114441d0c0a0452fd599bf21d359b1b5f068dfc567"
    hash2       = "6a03793a4e6175c2a80395cdedba1eaf5878722aa36c4cbfae104768ed79890d"

  strings:
    $s1  = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){retur" ascii
    $s2  = "on fuck(){return \"MBg\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return " ascii
    $s3  = "{return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Wo0\";}" ascii
    $s4  = "ck(){return \"Ar\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";" ascii
    $s5  = "\"Cd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(func" ascii
    $s6  = ",(function fuck(){return \"Np\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){r" ascii
    $s7  = "n fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"" ascii
    $s8  = "urn \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Vb\";})(),(" ascii
    $s9  = "turn \"MBg\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})()," ascii
    $s10 = "urn \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Cd\";})(),(f" ascii
    $s11 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){ret" ascii
    $s12 = "urn \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"PDf\";})(),(" ascii
    $s13 = " fuck(){return \"Vb\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IP" ascii
    $s14 = "(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"PDf\";})(),(function fuck(" ascii
    $s15 = "nction fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){retu" ascii
    $s16 = ")(),(function fuck(){return \"Tv\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"XFd\";})(),(function fuck" ascii
    $s17 = "ck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"PDf" ascii
    $s18 = " fuck(){return \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IR" ascii
    $s19 = "function fuck(){return \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){retu" ascii
    $s20 = "(function fuck(){return \"GJx\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}