rule _20160921_30902cdec8afbffc64d0c0cd57e17570_20160921_af22e174703e_4847 {
  meta:
    description = "datamaliciousorder - from files 20160921_30902cdec8afbffc64d0c0cd57e17570.js, 20160921_af22e174703ebae0fa1368fd471dba37.js, 20160921_c58f55b02ed5bcc68d14314fe1cbe1f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "794f51b8ce9ffbf2858ed5522e027d4ca3155be961907d88f09dd5679b3f1a18"
    hash2       = "24c1540f49c4fe83a182058f70751619567afa9e8884c1dee7ae13e5fad14a59"
    hash3       = "9b14dd6c2f6263aca7c445e6160fdf64ae8e12248f26b67576668dd3b4f18382"

  strings:
    $s1 = "),(function fuck(){return \"Ff\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck()" ascii
    $s2 = "ck(){return \"Mw\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"LGo\"" ascii
    $s3 = "unction fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){re" ascii
    $s4 = "u\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s5 = " fuck(){return \"Za\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"I" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}