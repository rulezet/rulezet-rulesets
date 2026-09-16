rule _20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa_20160921_5745920040b3_4687 {
  meta:
    description = "datamaliciousorder - from files 20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa.js, 20160921_5745920040b3b3273f05bcfbefadb4d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8753bd153b88da9a4351b5d6a0111d7af66a0f18e8b8a42beee11ad2916dc183"
    hash2       = "86b6dab46ebbd6ed243e73b97070b8a7b74178533a419d7a22c3842a74574534"

  strings:
    $s1 = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return" ascii
    $s2 = " \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(func" ascii
    $s3 = "){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Ve\";})" ascii
    $s4 = "(function fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){r" ascii
    $s5 = "tion fuck(){return \"XHj\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}