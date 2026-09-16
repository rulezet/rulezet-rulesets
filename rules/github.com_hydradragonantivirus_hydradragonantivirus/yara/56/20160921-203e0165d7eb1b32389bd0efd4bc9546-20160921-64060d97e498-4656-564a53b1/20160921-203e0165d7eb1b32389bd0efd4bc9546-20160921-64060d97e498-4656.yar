rule _20160921_203e0165d7eb1b32389bd0efd4bc9546_20160921_64060d97e498_4656 {
  meta:
    description = "datamaliciousorder - from files 20160921_203e0165d7eb1b32389bd0efd4bc9546.js, 20160921_64060d97e498db57bf68dbb08be86bba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9112c30f4cc79af123a3f3e13b1e01a29f2419955988701cb25a673fdfe684d"
    hash2       = "30a02b9f75ed0112affe2c698cfdbe2ec2a5bc4d8248ac34ebe13e072bd212f0"

  strings:
    $s1 = "ion fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return " ascii
    $s2 = "tion fuck(){return \"UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return" ascii
    $s3 = "Kv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"RAi\";})(),(functio" ascii
    $s4 = "urn \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s5 = "ction fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}