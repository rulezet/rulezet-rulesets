rule _20160921_c01f87df9de4ce5ca88bd5f8e99b8421_20160921_d56a785468c6_2566 {
  meta:
    description = "datamaliciousorder - from files 20160921_c01f87df9de4ce5ca88bd5f8e99b8421.js, 20160921_d56a785468c6ab02ba1f7ee3a5eadcdb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "863f188b1216c3a7a1dc561983400a4e8b6fadded702cf47ee8533061495abc8"
    hash2       = "d5ca39f97274b051212868ee58d01e745bb87d0a12198dfdfbeb7c3965cbf540"

  strings:
    $s1 = "n fuck(){return \"OQr\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"U" ascii
    $s2 = "ck(){return \"Zy\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Vb\";}" ascii
    $s3 = "return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"MIl\";})(" ascii
    $s4 = "Wo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functio" ascii
    $s5 = "urn \"XCr\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"DRx\";})(),(f" ascii
    $s6 = "),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Py\";})(),(function fuck()" ascii
    $s7 = "function fuck(){return \"PDf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){r" ascii
    $s8 = "n \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}