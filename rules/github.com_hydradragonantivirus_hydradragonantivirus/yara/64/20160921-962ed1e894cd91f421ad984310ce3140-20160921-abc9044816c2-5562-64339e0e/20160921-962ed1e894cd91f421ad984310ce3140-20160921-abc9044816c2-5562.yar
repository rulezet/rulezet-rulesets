rule _20160921_962ed1e894cd91f421ad984310ce3140_20160921_abc9044816c2_5562 {
  meta:
    description = "datamaliciousorder - from files 20160921_962ed1e894cd91f421ad984310ce3140.js, 20160921_abc9044816c2455dc24ac338746b6bd5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ddab3f025feef0c562b4f7f707a08e5d6502c7b7178d3d6367d05bae0018033"
    hash2       = "2bb53920235afb1c2d16f013bc118d1df64065eefc10c1b2b9e7a4b133850850"

  strings:
    $s1 = " \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"RAi\";})(),(fu" ascii
    $s2 = "(){return \"TTs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";" ascii
    $s3 = "ion fuck(){return \"IKv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return " ascii
    $s4 = " \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(fu" ascii
    $s5 = "urn \"IPu\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Vb\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}