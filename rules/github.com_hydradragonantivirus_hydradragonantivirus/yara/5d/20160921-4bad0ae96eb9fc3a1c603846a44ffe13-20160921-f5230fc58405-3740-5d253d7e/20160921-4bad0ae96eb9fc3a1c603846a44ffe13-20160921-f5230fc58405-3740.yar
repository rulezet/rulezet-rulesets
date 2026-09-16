rule _20160921_4bad0ae96eb9fc3a1c603846a44ffe13_20160921_f5230fc58405_3740 {
  meta:
    description = "datamaliciousorder - from files 20160921_4bad0ae96eb9fc3a1c603846a44ffe13.js, 20160921_f5230fc58405f25233bda6815654bd6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a99f235f58613323f5c58def3503d47959f4a77f0697e30c75b6d221c4b40806"
    hash2       = "1a813dda7d0088c45bb00563ea79982995ec1337c805380117fe705f80c51c64"

  strings:
    $s1 = "(function fuck(){return \"MBg\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Na\";})(),(function fuck(){r" ascii
    $s2 = "u\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq\";})(),(function" ascii
    $s3 = "fuck(){return \"IOs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NK" ascii
    $s4 = "on fuck(){return \"YQt\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return " ascii
    $s5 = "turn \"Qh\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Yk\";})(),(f" ascii
    $s6 = "ck(){return \"CTm\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Dc\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}