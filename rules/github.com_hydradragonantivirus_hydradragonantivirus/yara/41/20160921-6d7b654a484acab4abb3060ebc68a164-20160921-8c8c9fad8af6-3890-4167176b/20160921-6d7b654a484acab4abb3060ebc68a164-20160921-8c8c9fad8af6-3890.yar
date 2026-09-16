rule _20160921_6d7b654a484acab4abb3060ebc68a164_20160921_8c8c9fad8af6_3890 {
  meta:
    description = "datamaliciousorder - from files 20160921_6d7b654a484acab4abb3060ebc68a164.js, 20160921_8c8c9fad8af659443108d1078847a668.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2840e0696eacd7118885eaede05c3ef29d9cc682ba227d7797a60be4872d86c9"
    hash2       = "05c35ee4072476c50081705469d125bb2570dea942839cab58bf87874667da59"

  strings:
    $s1 = "ction fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return" ascii
    $s2 = "n \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(fun" ascii
    $s3 = "(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";}" ascii
    $s4 = "n fuck(){return \"Hs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"G" ascii
    $s5 = " fuck(){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"L" ascii
    $s6 = "),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}