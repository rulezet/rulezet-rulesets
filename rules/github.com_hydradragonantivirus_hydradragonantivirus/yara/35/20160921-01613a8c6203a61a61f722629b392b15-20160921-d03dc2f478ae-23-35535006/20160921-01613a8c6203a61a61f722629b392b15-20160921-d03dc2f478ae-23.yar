rule _20160921_01613a8c6203a61a61f722629b392b15_20160921_d03dc2f478ae_23 {
  meta:
    description = "datamaliciousorder - from files 20160921_01613a8c6203a61a61f722629b392b15.js, 20160921_d03dc2f478ae343430b4a6dbcc9d6c08.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c3ee763f1740e8bc6ded9772aabbe3d3805d8cf2a023e0289a9b8a1a42624b7"
    hash2       = "dd1077874fb7f556e5acfe2ff0c2ed6b6c203fcdf442119ca307096446d90cd4"

  strings:
    $s1  = "n fuck(){return \"YAv\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"U" ascii
    $s2  = "){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})" ascii
    $s3  = "tion fuck(){return \"ZVi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s4  = "s\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"LGo\";})(),(function" ascii
    $s5  = "ck(){return \"CCb\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"RAi" ascii
    $s6  = "urn \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Tv\";})(),(function fuck(){return \"YQt\";})(),(" ascii
    $s7  = "){return \"TTs\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"UXf\";})" ascii
    $s8  = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){retur" ascii
    $s9  = "\"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"GNm\";})(),(func" ascii
    $s10 = "tion fuck(){return \"Wo\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return " ascii
    $s11 = "fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"N" ascii
    $s12 = "rn \"Xg\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s13 = "return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Cd\";})(" ascii
    $s14 = "){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Cd\";}" ascii
    $s15 = " fuck(){return \"Np\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"U" ascii
    $s16 = "k(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Py\"" ascii
    $s17 = "return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"UXf\";})()" ascii
    $s18 = "){return \"YQt\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";" ascii
    $s19 = "n fuck(){return \"Jo\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"I" ascii
    $s20 = "ction fuck(){return \"ADy\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}