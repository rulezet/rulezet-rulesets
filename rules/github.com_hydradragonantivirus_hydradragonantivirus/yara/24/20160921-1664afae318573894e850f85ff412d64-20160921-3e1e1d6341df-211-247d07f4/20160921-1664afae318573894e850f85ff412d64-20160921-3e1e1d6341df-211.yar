rule _20160921_1664afae318573894e850f85ff412d64_20160921_3e1e1d6341df_211 {
  meta:
    description = "datamaliciousorder - from files 20160921_1664afae318573894e850f85ff412d64.js, 20160921_3e1e1d6341df1caf923e4b9f79ea9ac3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c41fd157f38d62b8a8b91fe197ee0a409bd6fd7582b976184456d2447110138a"
    hash2       = "d858d56d343b97488263af92c96b6bee8f8213dd2aec4d79132b57f04ea3c568"

  strings:
    $s1  = "rn \"PDf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Cd\";})(),(f" ascii
    $s2  = "function fuck(){return \"We\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){re" ascii
    $s3  = "tion fuck(){return \"RAi\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s4  = "ck(){return \"Cd\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg" ascii
    $s5  = "turn \"UOe\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s6  = "turn \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})()," ascii
    $s7  = "n \"PDf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(fun" ascii
    $s8  = "urn \"USf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})()," ascii
    $s9  = "{return \"MBg\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"PDf\";}" ascii
    $s10 = "TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(functi" ascii
    $s11 = "(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Cd\";}" ascii
    $s12 = ",(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){" ascii
    $s13 = "(){return \"MOj\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";" ascii
    $s14 = "tion fuck(){return \"Np\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return " ascii
    $s15 = "n \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"NKq\";})(),(f" ascii
    $s16 = ";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\";})(),(function f" ascii
    $s17 = "uck(){return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"ADy" ascii
    $s18 = "urn \"MBg\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(" ascii
    $s19 = "IKv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"GNm\";})(),(functi" ascii
    $s20 = "rn \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"UOe\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}