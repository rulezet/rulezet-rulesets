rule _20160921_2f8fa7cee8a6f4f78978b7417f3f700e_20160921_6db2cb585eb9_3587 {
  meta:
    description = "datamaliciousorder - from files 20160921_2f8fa7cee8a6f4f78978b7417f3f700e.js, 20160921_6db2cb585eb933d83d07b47d979b00ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6410122a95cd840a4eef622389d8026475b4f6a156d4b5288cf227165c036c96"
    hash2       = "b98c5953d102d77c680619bcfd3ba762b3a28a14355f65c479544c745a7c9a12"

  strings:
    $s1 = "function fuck(){return \"Ug\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){ret" ascii
    $s2 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return" ascii
    $s3 = "(){return \"Zy\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Vb\";}" ascii
    $s4 = "b\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"To\";})(),(function" ascii
    $s5 = "{return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})" ascii
    $s6 = " \"IPu\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Vb\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}