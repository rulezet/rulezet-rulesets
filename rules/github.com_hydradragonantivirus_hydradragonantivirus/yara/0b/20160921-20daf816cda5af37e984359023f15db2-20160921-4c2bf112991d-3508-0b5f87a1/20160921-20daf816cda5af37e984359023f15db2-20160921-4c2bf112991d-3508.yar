rule _20160921_20daf816cda5af37e984359023f15db2_20160921_4c2bf112991d_3508 {
  meta:
    description = "datamaliciousorder - from files 20160921_20daf816cda5af37e984359023f15db2.js, 20160921_4c2bf112991da80cf65c9f462d7503be.js, 20160921_515ffdda2060abfddd0b1faaa82a6279.js, 20160921_9c64236400e63181393ce4bc58f634a5.js, 20160921_ad0fbcfca87e48302530672c4ceab093.js, 20160921_cff8867bbb427ac014f0546c00ad8427.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a45ccf6470d4ee194ed220125c42c5ac5d7c4b8a46cce738c6d12e9cc0bafea8"
    hash2       = "f2e5ee0ebdd9746b0055379071a47434cdd28be3788ad04e886f8bd01e0746c1"
    hash3       = "e66d45deceae626136192ed805b6d7d4dc1cb2be6956a53702353ef221f89c18"
    hash4       = "2b1d27f440a3f4232e02265ce38f6eee5a715bff67e056aca1a1c800909c0e37"
    hash5       = "481451a3850055fd2d398d5707171f67d2aa3cd019214d6b67f539efc81ca7bb"
    hash6       = "80a0b2154f5b0c87fb7ba82fc32a74807761d038a93d6da45f835417e93af3ef"

  strings:
    $s1 = "\"Yk\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"DRx\";})(),(funct" ascii
    $s2 = "),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Za\";})(),(function fuck(){" ascii
    $s3 = ";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"ZWu\";})(),(function fu" ascii
    $s4 = "){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"DAa\";}" ascii
    $s5 = "nction fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){retu" ascii
    $s6 = " \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"ADy\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}