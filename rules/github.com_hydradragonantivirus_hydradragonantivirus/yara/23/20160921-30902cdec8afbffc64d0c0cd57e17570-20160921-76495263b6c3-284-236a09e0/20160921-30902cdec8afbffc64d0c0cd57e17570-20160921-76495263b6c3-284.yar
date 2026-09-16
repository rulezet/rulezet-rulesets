rule _20160921_30902cdec8afbffc64d0c0cd57e17570_20160921_76495263b6c3_284 {
  meta:
    description = "datamaliciousorder - from files 20160921_30902cdec8afbffc64d0c0cd57e17570.js, 20160921_76495263b6c3d9e46a0608d3374ceee3.js, 20160921_79ed56ce6462f4777520d97fc535fdf5.js, 20160921_c58f55b02ed5bcc68d14314fe1cbe1f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "794f51b8ce9ffbf2858ed5522e027d4ca3155be961907d88f09dd5679b3f1a18"
    hash2       = "7cff9275d0250bfdb50a193691ce5f5102aebf80af9793212683e5ddde59dc73"
    hash3       = "eeffea004f5e955937d1ae0a312f76837c366f381494eff12911d267efcb2e6a"
    hash4       = "9b14dd6c2f6263aca7c445e6160fdf64ae8e12248f26b67576668dd3b4f18382"

  strings:
    $s1  = "MBg\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(funct" ascii
    $s2  = " \"ADy\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s3  = "ck(){return \"Cd\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg" ascii
    $s4  = " \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"USf\";})(),(fu" ascii
    $s5  = "RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(functi" ascii
    $s6  = "function fuck(){return \"Cd\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){ret" ascii
    $s7  = "ion fuck(){return \"MBg\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return" ascii
    $s8  = "fuck(){return \"TTs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Vb" ascii
    $s9  = "\"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(fun" ascii
    $s10 = "turn \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})()" ascii
    $s11 = "function fuck(){return \"PDf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){r" ascii
    $s12 = "){return \"LGo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"PDf\";}" ascii
    $s13 = "ction fuck(){return \"MBg\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){retu" ascii
    $s14 = "ion fuck(){return \"CTm\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return " ascii
    $s15 = " fuck(){return \"MBg\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"I" ascii
    $s16 = "urn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"GJx\";})()," ascii
    $s17 = "k(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\"" ascii
    $s18 = "on fuck(){return \"PDf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s19 = "ck(){return \"PDf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm" ascii
    $s20 = "ck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Cd" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}