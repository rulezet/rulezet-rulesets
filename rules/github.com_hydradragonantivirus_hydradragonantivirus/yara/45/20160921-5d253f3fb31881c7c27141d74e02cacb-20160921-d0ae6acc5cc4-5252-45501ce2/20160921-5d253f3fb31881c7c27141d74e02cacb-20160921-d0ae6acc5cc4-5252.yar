rule _20160921_5d253f3fb31881c7c27141d74e02cacb_20160921_d0ae6acc5cc4_5252 {
  meta:
    description = "datamaliciousorder - from files 20160921_5d253f3fb31881c7c27141d74e02cacb.js, 20160921_d0ae6acc5cc4f52f8d5df0b47ef8659a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae85fe56260e8c9a1243da145f7594a08ac59bd50027af5e54b6d04e82f44e88"
    hash2       = "8cde265a6a44d9e9f86f351959c030a86800d101b5b5ca057ac1cdc5c5a1e38d"

  strings:
    $s1 = "fuck(){return \"CCb\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"I" ascii
    $s2 = "(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Na\";})(),(function fuck(){re" ascii
    $s3 = "(function fuck(){return \"DWe\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){" ascii
    $s4 = "(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";}" ascii
    $s5 = "{return \"DWe\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}