rule _20160921_940fdd83fcdf499d0ebc071f779bd880_20160921_c4701eeb8c19_2543 {
  meta:
    description = "datamaliciousorder - from files 20160921_940fdd83fcdf499d0ebc071f779bd880.js, 20160921_c4701eeb8c1954cdca7ebff879af825b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b73c87ed73bc62067299b13aaa227535cbedafa1a7f74ad02273d1aad3a3449f"
    hash2       = "434597ea9990301d4bb62f8905b136fc4a13b61d61fa5eeef5efdc7757f1f1bc"

  strings:
    $s1 = ",(function fuck(){return \"Oh\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){r" ascii
    $s2 = "IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Ik\";})(),(function" ascii
    $s3 = "(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){r" ascii
    $s4 = "n fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"" ascii
    $s5 = "{return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Ve\";})(" ascii
    $s6 = "\"Av\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(func" ascii
    $s7 = "IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Cd\";})(),(functio" ascii
    $s8 = "on fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}