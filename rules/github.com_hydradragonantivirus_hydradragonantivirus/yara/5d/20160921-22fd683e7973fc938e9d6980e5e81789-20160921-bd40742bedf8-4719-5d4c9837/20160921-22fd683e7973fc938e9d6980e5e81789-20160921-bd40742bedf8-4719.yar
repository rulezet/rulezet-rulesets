rule _20160921_22fd683e7973fc938e9d6980e5e81789_20160921_bd40742bedf8_4719 {
  meta:
    description = "datamaliciousorder - from files 20160921_22fd683e7973fc938e9d6980e5e81789.js, 20160921_bd40742bedf80aa0091b1fafd0a7ba4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3583ada9b0a35137add948ee4bd3182a5f977a0dbcc3a39c01ee288f703d566"
    hash2       = "85233a675e78f03dbcaaf2a32253b0d4a36e5c5e7008041477e560a514d38729"

  strings:
    $s1 = "(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){r" ascii
    $s2 = "fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"O" ascii
    $s3 = "fuck(){return \"IKv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"I" ascii
    $s4 = " \"OQr\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(fun" ascii
    $s5 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Ff\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}