rule _20160921_7c37cf57d8ed1c10fea15c60dc79c0c8_20160921_832521e32124_68 {
  meta:
    description = "datamaliciousorder - from files 20160921_7c37cf57d8ed1c10fea15c60dc79c0c8.js, 20160921_832521e32124647e5f9543472346f319.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3acecff4ec35ade7d618cbd511372d6023de7d591317c5e6ce95fc088b8cf6e"
    hash2       = "7d8db496c31215a3730a6ed92a0e2b36ff0fe0e9ddaf7405680d1002474263e1"

  strings:
    $s1  = "k(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"GNm\";" ascii
    $s2  = "unction fuck(){return \"XCr\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){retu" ascii
    $s3  = "{return \"MIl\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";}" ascii
    $s4  = "urn \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"NKq\";})()," ascii
    $s5  = "ion fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"" ascii
    $s6  = "\"Py\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"YQt\";})(),(func" ascii
    $s7  = "turn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Oh\";})(),(" ascii
    $s8  = "k(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\"" ascii
    $s9  = "n fuck(){return \"ADy\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s10 = " \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"ADy\";})(),(fun" ascii
    $s11 = "rn \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(fu" ascii
    $s12 = "unction fuck(){return \"XCr\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s13 = "urn \"ADy\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(" ascii
    $s14 = "on fuck(){return \"PDf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return " ascii
    $s15 = "n fuck(){return \"ADy\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"" ascii
    $s16 = "turn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"ZWu\";})()," ascii
    $s17 = "\"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"DAa\";})(),(funct" ascii
    $s18 = "eturn \"USf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})()," ascii
    $s19 = "turn \"TTs\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})()" ascii
    $s20 = "n \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"GNm\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}