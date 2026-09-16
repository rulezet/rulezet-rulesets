rule _20160921_44880573519212a90b7d910319fc31d8_20160921_7c5b5eaba938_1577 {
  meta:
    description = "datamaliciousorder - from files 20160921_44880573519212a90b7d910319fc31d8.js, 20160921_7c5b5eaba938fa91eb6a9414212e13f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8427ee610833efbf68884e3ec13c4357ae35e1aa0bf8ddc2ffe99b9a7f44fb40"
    hash2       = "9b25331c24a00cfccf7bf1604f7df1d245543734bf5553f0a7c3c911bb74cbb8"

  strings:
    $s1  = "n fuck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii
    $s2  = "turn \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s3  = "Il\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(functio" ascii
    $s4  = "{return \"Nm\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ve\";})(" ascii
    $s5  = "a\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"ZWu\";})(),(functio" ascii
    $s6  = "),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){" ascii
    $s7  = "n \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"NKq\";})(),(fun" ascii
    $s8  = ";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"CCb\";})(),(function fu" ascii
    $s9  = "ion fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii
    $s10 = "nction fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){retu" ascii
    $s11 = "ck(){return \"To\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\"" ascii
    $s12 = "ion fuck(){return \"Ar\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}