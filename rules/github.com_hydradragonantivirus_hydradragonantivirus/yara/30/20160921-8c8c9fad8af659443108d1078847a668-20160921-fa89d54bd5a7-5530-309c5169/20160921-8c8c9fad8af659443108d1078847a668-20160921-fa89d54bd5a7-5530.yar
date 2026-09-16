rule _20160921_8c8c9fad8af659443108d1078847a668_20160921_fa89d54bd5a7_5530 {
  meta:
    description = "datamaliciousorder - from files 20160921_8c8c9fad8af659443108d1078847a668.js, 20160921_fa89d54bd5a7a27defe09d5a56b5a881.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05c35ee4072476c50081705469d125bb2570dea942839cab58bf87874667da59"
    hash2       = "30f2a7c2562ef79254c8129be50246b9c41eb24f000c8cfbd0f4f8c28b49b00f"

  strings:
    $s1 = "return \"Oh\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IRn\";})()" ascii
    $s2 = "(function fuck(){return \"MBg\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){re" ascii
    $s3 = "tion fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return" ascii
    $s4 = "nction fuck(){return \"DHd\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){ret" ascii
    $s5 = "tion fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}