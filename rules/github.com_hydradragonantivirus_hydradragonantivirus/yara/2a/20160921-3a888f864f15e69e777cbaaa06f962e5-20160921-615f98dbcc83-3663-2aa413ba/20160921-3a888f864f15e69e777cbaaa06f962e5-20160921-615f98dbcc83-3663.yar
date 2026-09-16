rule _20160921_3a888f864f15e69e777cbaaa06f962e5_20160921_615f98dbcc83_3663 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a888f864f15e69e777cbaaa06f962e5.js, 20160921_615f98dbcc83e57c9789ba9d89e188d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65826487c59973db0339cbaf1f8e99201516dc26d5bdf1991855fafe9cbc5da1"
    hash2       = "3ee4da5f56533720f6cb24f55125aadc635f7464c5c8a7fbc14e3949f44d0ee5"

  strings:
    $s1 = "on fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return " ascii
    $s2 = "u\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Jh\";})(),(function " ascii
    $s3 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){retur" ascii
    $s4 = "return \"CCb\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s5 = "{return \"UXf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";}" ascii
    $s6 = "ion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}