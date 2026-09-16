rule _20160921_3282034bab74b3776acf585e8adfca92_20160921_b6523fd99592_3605 {
  meta:
    description = "datamaliciousorder - from files 20160921_3282034bab74b3776acf585e8adfca92.js, 20160921_b6523fd99592b93c7a07e8a0e3a5eaf2.js, 20160921_ba57fd323c757d83bd9bb08cdba3b4a4.js, 20160921_d82f642339947ac5ef4d322534d8cd70.js, 20160921_efc4e68608b4bd36f7e16eb4722b21c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b99efa289490e150d7af72ae3e0fb067880b4a22c16ba75dec34f9945b5c2df"
    hash2       = "c7380d8ae5ab67e50f821f2074c7903d887706b91f0b0d3dcfedf5bfbd9a62e0"
    hash3       = "119b312aafd59cd12991442685e391e8850e3417b81d4aa79ae8e5c89a75f170"
    hash4       = "1af101b4afb2b8d290446a4841d803e88cb42849fb95f0cea056677487805eb6"
    hash5       = "fe50eec4105613d48ac273c2d63a5b952098f339f7f06871b77053c43642dba7"

  strings:
    $s1 = "on fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s2 = "turn \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"USf\";})()" ascii
    $s3 = "\"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"GNm\";})(),(funct" ascii
    $s4 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return " ascii
    $s5 = "return \"Np\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})()" ascii
    $s6 = "UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"USf\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}