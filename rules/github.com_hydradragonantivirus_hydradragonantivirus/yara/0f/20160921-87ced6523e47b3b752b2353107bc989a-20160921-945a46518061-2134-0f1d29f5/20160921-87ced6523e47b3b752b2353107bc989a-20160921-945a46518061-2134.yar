rule _20160921_87ced6523e47b3b752b2353107bc989a_20160921_945a46518061_2134 {
  meta:
    description = "datamaliciousorder - from files 20160921_87ced6523e47b3b752b2353107bc989a.js, 20160921_945a46518061bd8e157aed251e0ffa9e.js, 20160921_d29f34806a7d94f2bbb7a733fc4c43bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46c521beb23d37cfa4d60cfcab38c941734971fe3102123b7e4c2813544d39b6"
    hash2       = "cc3d236edb3b45a767b438fa21243a07176d6f5def724e03e45aca76b3127054"
    hash3       = "70ffc02d6ba6dee7d11e2b608cd1544f99d837ffc746455c17b70d5b07ba0ac9"

  strings:
    $s1 = "(),(function fuck(){return \"Tv\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){" ascii
    $s2 = " fuck(){return \"USf\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"M" ascii
    $s3 = "){return \"We\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"NKq\";})" ascii
    $s4 = "Ot\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(functi" ascii
    $s5 = " fuck(){return \"Et\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"B" ascii
    $s6 = "n fuck(){return \"Nm\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"I" ascii
    $s7 = "n \"Dc\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Yk\";})(),(fun" ascii
    $s8 = "k\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jh\";})(),(function " ascii
    $s9 = "n fuck(){return \"Jh\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"E" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}