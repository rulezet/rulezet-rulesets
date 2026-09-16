rule _20160921_ba57fd323c757d83bd9bb08cdba3b4a4_20160921_c38068bdcf61_280 {
  meta:
    description = "datamaliciousorder - from files 20160921_ba57fd323c757d83bd9bb08cdba3b4a4.js, 20160921_c38068bdcf6149dc68d38cbcccfe991f.js, 20160921_d4b576a05afdcd9649d02e422feb16d3.js, 20160921_efc4e68608b4bd36f7e16eb4722b21c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "119b312aafd59cd12991442685e391e8850e3417b81d4aa79ae8e5c89a75f170"
    hash2       = "d59dd40562ac50a453dbb7054114c62cfd7c63d24b81c776b35af40fb9aa3480"
    hash3       = "221c028d5b96ed7d5655800598b47b367ee2d1927826d126b5808db32c9a01f2"
    hash4       = "fe50eec4105613d48ac273c2d63a5b952098f339f7f06871b77053c43642dba7"

  strings:
    $s1  = "urn \"PDf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(f" ascii
    $s2  = "tion fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return" ascii
    $s3  = "\"GNm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(func" ascii
    $s4  = "rn \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"NKq\";})(),(fu" ascii
    $s5  = "uck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"GN" ascii
    $s6  = "\"Ve\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"YQt\";})(),(func" ascii
    $s7  = "ction fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){retu" ascii
    $s8  = "nction fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){retu" ascii
    $s9  = "eturn \"Dc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Wo0\";})()" ascii
    $s10 = "(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"NKq\";})(),(function fuck(" ascii
    $s11 = "uck(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IP" ascii
    $s12 = " fuck(){return \"Np\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"I" ascii
    $s13 = "LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(functi" ascii
    $s14 = "){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Cd\";})" ascii
    $s15 = "k(){return \"Ve\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Cd\";" ascii
    $s16 = "),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){" ascii
    $s17 = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){retur" ascii
    $s18 = "(function fuck(){return \"MBg\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){r" ascii
    $s19 = "k(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"LGo" ascii
    $s20 = "rn \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}