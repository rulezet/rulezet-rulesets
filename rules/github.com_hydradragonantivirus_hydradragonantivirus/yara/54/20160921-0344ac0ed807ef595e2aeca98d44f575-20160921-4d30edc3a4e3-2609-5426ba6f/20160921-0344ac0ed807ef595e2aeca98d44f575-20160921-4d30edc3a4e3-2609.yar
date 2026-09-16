rule _20160921_0344ac0ed807ef595e2aeca98d44f575_20160921_4d30edc3a4e3_2609 {
  meta:
    description = "datamaliciousorder - from files 20160921_0344ac0ed807ef595e2aeca98d44f575.js, 20160921_4d30edc3a4e3226feee5b6289df9e399.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f631e328f07a7c3d34221081061f64d96da25c4f05169c427adb507bb6941f58"
    hash2       = "d28b5e72375443a9ef1a43fee185a0e5563672a0764eef4f58a90a27302162ea"

  strings:
    $s1 = "rn \"IPu\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(f" ascii
    $s2 = "),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){" ascii
    $s3 = "rn \"LGo\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s4 = "rn \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"ADy\";})(),(" ascii
    $s5 = "(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"UOe\";})(),(function fuck(" ascii
    $s6 = "function fuck(){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){ret" ascii
    $s7 = " fuck(){return \"Ot\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"I" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}