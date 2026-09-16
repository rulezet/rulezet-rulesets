rule _20160921_5a42eec12fd0d8c1d5256852068b87b8_20160921_f575ae0885e7_5241 {
  meta:
    description = "datamaliciousorder - from files 20160921_5a42eec12fd0d8c1d5256852068b87b8.js, 20160921_f575ae0885e764a3ea3a621283d492e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54a7451a184fd8afa3cac9d787d5f83abeb8fecd14d9f136cff135e9f0d849e0"
    hash2       = "56a063ba0d781a52d612f976f937d59e64bb8200cf3c4b448f3cb3013733bdaf"

  strings:
    $s1 = "rn \"Tv\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Na\";})(),(fun" ascii
    $s2 = "return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"AUx\";})" ascii
    $s3 = "n \"Xg\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(fu" ascii
    $s4 = "),(function fuck(){return \"Vb\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){" ascii
    $s5 = "return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"AUx\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}