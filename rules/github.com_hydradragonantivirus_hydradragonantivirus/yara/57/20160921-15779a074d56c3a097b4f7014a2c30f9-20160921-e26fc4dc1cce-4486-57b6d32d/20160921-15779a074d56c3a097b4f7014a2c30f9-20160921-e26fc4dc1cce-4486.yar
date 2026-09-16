rule _20160921_15779a074d56c3a097b4f7014a2c30f9_20160921_e26fc4dc1cce_4486 {
  meta:
    description = "datamaliciousorder - from files 20160921_15779a074d56c3a097b4f7014a2c30f9.js, 20160921_e26fc4dc1ccef911251bba0675c76ce0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aac4640bf20c6d05cb7c57f9703d60beee7ea9dfc98b851cabc5976b3d117b8d"
    hash2       = "f1074dcd9f3ae62af13634c9f88af0a235b2e315a2697fc222ce96bad51ca1a1"

  strings:
    $s1 = "(){return \"IOs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";" ascii
    $s2 = "Il\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(functi" ascii
    $s3 = "unction fuck(){return \"GJx\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){re" ascii
    $s4 = "k(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\"" ascii
    $s5 = "){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}