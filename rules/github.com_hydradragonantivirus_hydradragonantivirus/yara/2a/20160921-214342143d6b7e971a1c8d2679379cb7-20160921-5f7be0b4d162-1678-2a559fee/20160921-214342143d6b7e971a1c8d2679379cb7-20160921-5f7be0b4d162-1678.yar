rule _20160921_214342143d6b7e971a1c8d2679379cb7_20160921_5f7be0b4d162_1678 {
  meta:
    description = "datamaliciousorder - from files 20160921_214342143d6b7e971a1c8d2679379cb7.js, 20160921_5f7be0b4d162caa40e1fc5a06f9f867a.js, 20160921_e6b8063519cd61bbba9375bf86215501.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8dcc208c118a95c2f88df14e844ed832ee1e06bdf992329e8a721bd7aaa936e8"
    hash2       = "9a6e02fec1a6c5d0a6813da97edfb28eb017c5563b8e8c2205eb08ae1c6ec4e3"
    hash3       = "70ad2f9c8f844d4c80b1d4ce0f71f62f74e64671ae11d2d3af8e6ec764993403"

  strings:
    $s1  = "urn \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"USf\";})(),(" ascii
    $s2  = "\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Hs\";})(),(function f" ascii
    $s3  = "b\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s4  = "k(){return \"Py\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";" ascii
    $s5  = "on fuck(){return \"USf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s6  = " fuck(){return \"Py\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"H" ascii
    $s7  = "{return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})" ascii
    $s8  = " fuck(){return \"IPu\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"P" ascii
    $s9  = "tion fuck(){return \"TTs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return" ascii
    $s10 = "{return \"LLv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})" ascii
    $s11 = "n \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"LGo\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}