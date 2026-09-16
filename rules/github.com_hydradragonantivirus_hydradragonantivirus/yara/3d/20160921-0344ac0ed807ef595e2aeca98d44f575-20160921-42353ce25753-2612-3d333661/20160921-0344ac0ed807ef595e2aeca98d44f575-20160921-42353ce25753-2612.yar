rule _20160921_0344ac0ed807ef595e2aeca98d44f575_20160921_42353ce25753_2612 {
  meta:
    description = "datamaliciousorder - from files 20160921_0344ac0ed807ef595e2aeca98d44f575.js, 20160921_42353ce257534ed06a8c73cebdde12dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f631e328f07a7c3d34221081061f64d96da25c4f05169c427adb507bb6941f58"
    hash2       = "68261e17878fc3b618b0fec34ae97fb6fea1090c52fff206192cb972d23b2b35"

  strings:
    $s1 = "\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"LGo\";})(),(function " ascii
    $s2 = "turn \"XFd\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s3 = "unction fuck(){return \"TTs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){ret" ascii
    $s4 = "){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"NKq\";})" ascii
    $s5 = ")(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuc" ascii
    $s6 = "ck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Dc" ascii
    $s7 = "{return \"Ve\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}