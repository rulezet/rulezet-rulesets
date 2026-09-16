rule _20160921_65ff2a70ce98d58243fbbdf4849b9c40_20160921_99220520e874_3862 {
  meta:
    description = "datamaliciousorder - from files 20160921_65ff2a70ce98d58243fbbdf4849b9c40.js, 20160921_99220520e87414c0f2e1267cf4078a22.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4be01014513bc9c23e14a62953fb7d9f955467208a844109b10c685b1f9c4f29"
    hash2       = "5b655a405ebc3a6ee1687faec5788f37e732bcfe1afd9f30936ca55a4983a755"

  strings:
    $s1 = "ck(){return \"Sx\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi" ascii
    $s2 = "turn \"OQr\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Sx\";})(),(" ascii
    $s3 = "ck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"LGo" ascii
    $s4 = "b\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cs\";})(),(function" ascii
    $s5 = "function fuck(){return \"UOe\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){r" ascii
    $s6 = " fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}