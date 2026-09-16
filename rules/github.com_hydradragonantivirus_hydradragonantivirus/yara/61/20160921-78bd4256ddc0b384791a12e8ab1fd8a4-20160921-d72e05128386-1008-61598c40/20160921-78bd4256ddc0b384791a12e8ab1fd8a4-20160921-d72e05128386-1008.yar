rule _20160921_78bd4256ddc0b384791a12e8ab1fd8a4_20160921_d72e05128386_1008 {
  meta:
    description = "datamaliciousorder - from files 20160921_78bd4256ddc0b384791a12e8ab1fd8a4.js, 20160921_d72e05128386ec5185fa7c82a29fe618.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c64d081235a424574ab6bbe64470cbee71a700f01b638afac6d0954ebc5cc0a0"
    hash2       = "72502e65294651208a74590dc961703c09931d4341f59214d7303b271ca8abd5"

  strings:
    $s1  = "return \"MBg\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"FJs\";})(" ascii
    $s2  = "OQr\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(funct" ascii
    $s3  = "urn \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"ZWu\";})(),(" ascii
    $s4  = "){return \"To\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})" ascii
    $s5  = "uck(){return \"OQr\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MUs" ascii
    $s6  = "k(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Py\";}" ascii
    $s7  = "nction fuck(){return \"OQr\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s8  = "k(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Qh\"" ascii
    $s9  = " \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(func" ascii
    $s10 = "IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(funct" ascii
    $s11 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii
    $s12 = "unction fuck(){return \"GWo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){re" ascii
    $s13 = "rn \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ff\";})(),(function fuck(){return \"MBg\";})(),(f" ascii
    $s14 = "return \"IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})" ascii
    $s15 = "k(){return \"NKq\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\"" ascii
    $s16 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return" ascii
    $s17 = " fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"V" ascii
    $s18 = "})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuc" ascii
    $s19 = "){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"MOj\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}