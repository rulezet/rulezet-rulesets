rule _20160921_5a42eec12fd0d8c1d5256852068b87b8_20160921_fec97a223836_3813 {
  meta:
    description = "datamaliciousorder - from files 20160921_5a42eec12fd0d8c1d5256852068b87b8.js, 20160921_fec97a223836973c5d09ac6d41b2ad43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54a7451a184fd8afa3cac9d787d5f83abeb8fecd14d9f136cff135e9f0d849e0"
    hash2       = "d8c26b92e119ca52cb4c0aa43351cde4400c3d6abac819e57a391628e14280cb"

  strings:
    $s1 = "on fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"We\";})(),(function fuck(){return " ascii
    $s2 = ")(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Jo\";})(),(function fuck(" ascii
    $s3 = "ck(){return \"AUx\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug" ascii
    $s4 = ";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Xg\";})(),(function fuck" ascii
    $s5 = "ck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Wo0" ascii
    $s6 = "turn \"TTs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"ADy\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}