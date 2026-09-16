rule _20160921_3282034bab74b3776acf585e8adfca92_20160921_694d4629e99f_4875 {
  meta:
    description = "datamaliciousorder - from files 20160921_3282034bab74b3776acf585e8adfca92.js, 20160921_694d4629e99fd1d23d60bc73e0e28e30.js, 20160921_a05dfc337c4ada28e05759b304eef904.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b99efa289490e150d7af72ae3e0fb067880b4a22c16ba75dec34f9945b5c2df"
    hash2       = "01147c2f2f43df58f5a1b60481a04add7d73eba030abaeed3f9dedb1fd3574e4"
    hash3       = "db6a3cf7e8281867bf38b22cce5a945336377679a1a85ee91d365e41ec94182c"

  strings:
    $s1 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return" ascii
    $s2 = "\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"DRx\";})(),(function " ascii
    $s3 = "return \"XCr\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(" ascii
    $s4 = "nction fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){retur" ascii
    $s5 = "(){return \"Hs\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"DRx\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}