rule _20160921_67612c4ac75c1d3511dd9358b66e9fc5_20160921_d56a785468c6_3021 {
  meta:
    description = "datamaliciousorder - from files 20160921_67612c4ac75c1d3511dd9358b66e9fc5.js, 20160921_d56a785468c6ab02ba1f7ee3a5eadcdb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbf6986e3a8c7defa5c14d80cff4f3b3ce1db859ea94044f5d024758684178c0"
    hash2       = "d5ca39f97274b051212868ee58d01e745bb87d0a12198dfdfbeb7c3965cbf540"

  strings:
    $s1 = ",(function fuck(){return \"XFd\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){" ascii
    $s2 = "(function fuck(){return \"MIl\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){" ascii
    $s3 = "function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){re" ascii
    $s4 = "fuck(){return \"GJx\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"W" ascii
    $s5 = "ck(){return \"Jo\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"ADy" ascii
    $s6 = "uck(){return \"CCb\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"DRx" ascii
    $s7 = "urn \"Wo\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"DRx\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}