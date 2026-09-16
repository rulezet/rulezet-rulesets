rule _20160921_0344ac0ed807ef595e2aeca98d44f575_20160921_b0c04db09e98_4150 {
  meta:
    description = "datamaliciousorder - from files 20160921_0344ac0ed807ef595e2aeca98d44f575.js, 20160921_b0c04db09e980eb82ccee9091ca50467.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f631e328f07a7c3d34221081061f64d96da25c4f05169c427adb507bb6941f58"
    hash2       = "9e020a4a8174eebc9bdfd2c370a1a8a86e255e968f9dc218329e9d5912ba227b"

  strings:
    $s1 = "){return \"GJx\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"IRn\";}" ascii
    $s2 = "n \"Jo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(fu" ascii
    $s3 = "Go\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"MOj\";})(),(function" ascii
    $s4 = "k(){return \"Jo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";" ascii
    $s5 = "rn \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}