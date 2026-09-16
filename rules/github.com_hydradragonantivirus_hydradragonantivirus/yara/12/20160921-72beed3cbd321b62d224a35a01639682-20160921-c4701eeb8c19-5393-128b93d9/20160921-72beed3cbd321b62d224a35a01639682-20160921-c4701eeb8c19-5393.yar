rule _20160921_72beed3cbd321b62d224a35a01639682_20160921_c4701eeb8c19_5393 {
  meta:
    description = "datamaliciousorder - from files 20160921_72beed3cbd321b62d224a35a01639682.js, 20160921_c4701eeb8c1954cdca7ebff879af825b.js, 20160921_f1bb498dcbb1f3aecbc35886be394f58.js, 20160921_f7fa978ba93ca4504da33fc02cbf7f53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce3c3a93d2e5df0f850da4d79a5f697eaff66f1043058d62f80adad98b476839"
    hash2       = "434597ea9990301d4bb62f8905b136fc4a13b61d61fa5eeef5efdc7757f1f1bc"
    hash3       = "486454370a5dac6af41bfda9ac339e37120334ce5f7c4319bd0f8e9df9514b44"
    hash4       = "8c8d20603b0870465254e9f226f52f020b5b1d986c61571e7a3097b32ea728e0"

  strings:
    $s1 = "(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\"" ascii
    $s2 = "g\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Vb\";})(),(function" ascii
    $s3 = "nction fuck(){return \"GNm\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retu" ascii
    $s4 = "ion fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return" ascii
    $s5 = "ction fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}