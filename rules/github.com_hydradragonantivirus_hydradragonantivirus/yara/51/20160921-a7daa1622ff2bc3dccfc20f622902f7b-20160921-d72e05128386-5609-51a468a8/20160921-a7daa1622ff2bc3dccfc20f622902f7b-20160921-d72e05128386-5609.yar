rule _20160921_a7daa1622ff2bc3dccfc20f622902f7b_20160921_d72e05128386_5609 {
  meta:
    description = "datamaliciousorder - from files 20160921_a7daa1622ff2bc3dccfc20f622902f7b.js, 20160921_d72e05128386ec5185fa7c82a29fe618.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4caa07134c114c6f14592ae1a6f87a08bd21b6048c96d44b5eb70d9762008059"
    hash2       = "72502e65294651208a74590dc961703c09931d4341f59214d7303b271ca8abd5"

  strings:
    $s1 = "\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function f" ascii
    $s2 = "uck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb" ascii
    $s3 = "ction fuck(){return \"Ar\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){retur" ascii
    $s4 = "\"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MOj\";})(),(func" ascii
    $s5 = "){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}