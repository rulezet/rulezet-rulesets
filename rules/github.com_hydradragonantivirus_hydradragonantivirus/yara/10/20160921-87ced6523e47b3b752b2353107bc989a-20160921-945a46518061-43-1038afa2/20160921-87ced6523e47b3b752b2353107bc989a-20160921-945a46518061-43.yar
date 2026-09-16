rule _20160921_87ced6523e47b3b752b2353107bc989a_20160921_945a46518061_43 {
  meta:
    description = "datamaliciousorder - from files 20160921_87ced6523e47b3b752b2353107bc989a.js, 20160921_945a46518061bd8e157aed251e0ffa9e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46c521beb23d37cfa4d60cfcab38c941734971fe3102123b7e4c2813544d39b6"
    hash2       = "cc3d236edb3b45a767b438fa21243a07176d6f5def724e03e45aca76b3127054"

  strings:
    $s1  = "unction fuck(){return \"RAi\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Et\";})(),(function fuck(){retu" ascii
    $s2  = "uck(){return \"DRx\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"YAv" ascii
    $s3  = "uck(){return \"Ve\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"DRx\"" ascii
    $s4  = "a\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(function" ascii
    $s5  = "\"Vf\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Et\";})(),(functio" ascii
    $s6  = "nction fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Et\";})(),(function fuck(){retu" ascii
    $s7  = ")(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"DWe\";})(),(function fuc" ascii
    $s8  = "function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Et\";})(),(function fuck(){re" ascii
    $s9  = "n fuck(){return \"Vb\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"D" ascii
    $s10 = "\"Ai\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(func" ascii
    $s11 = "ion fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return" ascii
    $s12 = "rn \"IPu\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s13 = "Na\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Jh\";})(),(functio" ascii
    $s14 = ";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Et\";})(),(function fuc" ascii
    $s15 = "n fuck(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"" ascii
    $s16 = "})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"DRx\";})(),(function fuc" ascii
    $s17 = "urn \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Za\";})(),(fu" ascii
    $s18 = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"To\";})(),(function f" ascii
    $s19 = "k(){return \"ZLd\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"TTs" ascii
    $s20 = "eturn \"UOe\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ai\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}