rule _20160921_18f3609106b0af59da0b1200fe14abc1_20160921_615f98dbcc83_4558 {
  meta:
    description = "datamaliciousorder - from files 20160921_18f3609106b0af59da0b1200fe14abc1.js, 20160921_615f98dbcc83e57c9789ba9d89e188d0.js, 20160921_e4c63c3b699efd2f5fe2739b016a938a.js, 20160921_ef5539a74fa92cc432f92987e238b0be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95fb9e6292746461417b0e539747d500c780ad17cb775a9db031f77eaa53a3e2"
    hash2       = "3ee4da5f56533720f6cb24f55125aadc635f7464c5c8a7fbc14e3949f44d0ee5"
    hash3       = "9d5d6c2986818649619806d890aad49cda8d0da47fe67f38388e5441a53382a0"
    hash4       = "6a7080b4743207e49b99932d406b2ee18d652ac2222bdb5a88a66af8dea13c80"

  strings:
    $s1 = "function fuck(){return \"Xg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){re" ascii
    $s2 = " fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"P" ascii
    $s3 = " \"Py\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(fun" ascii
    $s4 = "(){return \"Xg\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Xw\";}" ascii
    $s5 = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}