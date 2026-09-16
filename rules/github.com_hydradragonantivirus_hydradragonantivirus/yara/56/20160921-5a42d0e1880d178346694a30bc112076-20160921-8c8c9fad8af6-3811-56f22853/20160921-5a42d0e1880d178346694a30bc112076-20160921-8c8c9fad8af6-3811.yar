rule _20160921_5a42d0e1880d178346694a30bc112076_20160921_8c8c9fad8af6_3811 {
  meta:
    description = "datamaliciousorder - from files 20160921_5a42d0e1880d178346694a30bc112076.js, 20160921_8c8c9fad8af659443108d1078847a668.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca8e81eec437e87b27dedb202751f13e736aa092e78fffde5fbf40616f2e3738"
    hash2       = "05c35ee4072476c50081705469d125bb2570dea942839cab58bf87874667da59"

  strings:
    $s1 = "ck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Hs" ascii
    $s2 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return" ascii
    $s3 = "ion fuck(){return \"IKv\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return" ascii
    $s4 = "eturn \"IPu\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"LGo\";})(" ascii
    $s5 = "urn \"UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s6 = "rn \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}