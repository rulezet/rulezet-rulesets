rule _20160921_65ff2a70ce98d58243fbbdf4849b9c40_20160921_e53844f4bb18_3861 {
  meta:
    description = "datamaliciousorder - from files 20160921_65ff2a70ce98d58243fbbdf4849b9c40.js, 20160921_e53844f4bb18305322896332fbd017e8.js, 20160921_f156e377f5219607c339e3053fbf1ae8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4be01014513bc9c23e14a62953fb7d9f955467208a844109b10c685b1f9c4f29"
    hash2       = "b8484bab412a47fffb0a694f32ca5de3480841bd1c0806d0a7e6e86dfd21de6c"
    hash3       = "05538f165c9450aa5ee129299544270acb99521d74bac943ca8cf157311609af"

  strings:
    $s1 = " fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"L" ascii
    $s2 = " \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii
    $s3 = "ck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"LGo" ascii
    $s4 = "ction fuck(){return \"OQr\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){retur" ascii
    $s5 = "urn \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(" ascii
    $s6 = "){return \"IOs\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"QTc\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}