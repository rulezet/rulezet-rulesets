rule _20160921_18f3609106b0af59da0b1200fe14abc1_20160921_72beed3cbd32_1803 {
  meta:
    description = "datamaliciousorder - from files 20160921_18f3609106b0af59da0b1200fe14abc1.js, 20160921_72beed3cbd321b62d224a35a01639682.js, 20160921_962ed1e894cd91f421ad984310ce3140.js, 20160921_c4701eeb8c1954cdca7ebff879af825b.js, 20160921_e4c63c3b699efd2f5fe2739b016a938a.js, 20160921_ef5539a74fa92cc432f92987e238b0be.js, 20160921_f1bb498dcbb1f3aecbc35886be394f58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95fb9e6292746461417b0e539747d500c780ad17cb775a9db031f77eaa53a3e2"
    hash2       = "ce3c3a93d2e5df0f850da4d79a5f697eaff66f1043058d62f80adad98b476839"
    hash3       = "5ddab3f025feef0c562b4f7f707a08e5d6502c7b7178d3d6367d05bae0018033"
    hash4       = "434597ea9990301d4bb62f8905b136fc4a13b61d61fa5eeef5efdc7757f1f1bc"
    hash5       = "9d5d6c2986818649619806d890aad49cda8d0da47fe67f38388e5441a53382a0"
    hash6       = "6a7080b4743207e49b99932d406b2ee18d652ac2222bdb5a88a66af8dea13c80"
    hash7       = "486454370a5dac6af41bfda9ac339e37120334ce5f7c4319bd0f8e9df9514b44"

  strings:
    $s1  = "rn \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"TTs\";})(),(fu" ascii
    $s2  = "IPu\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"ADy\";})(),(funct" ascii
    $s3  = "Vb\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(functio" ascii
    $s4  = "\"DHd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"LGo\";})(),(fun" ascii
    $s5  = "unction fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){ret" ascii
    $s6  = "(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MOj\"" ascii
    $s7  = "Rn\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(functi" ascii
    $s8  = "k(){return \"UOe\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii
    $s9  = "(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(" ascii
    $s10 = "urn \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}