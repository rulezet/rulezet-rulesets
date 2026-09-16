rule _20160921_65d76a5539546b98145997b9a44c1a09_20160921_afb633ee817d_1885 {
  meta:
    description = "datamaliciousorder - from files 20160921_65d76a5539546b98145997b9a44c1a09.js, 20160921_afb633ee817d9b15b91ed82a059939fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a1b81d7435f521382a4cec07d80cbc8fe75f2ebac92fb6c4d105b19ec098560"
    hash2       = "7a4e330bd3ec71aa3dc8fd3d5b2fa656b04d49cb5ee4e5478a50a6336c5bf9e5"

  strings:
    $s1  = "Kq\";})(),(function fuck(){return \"ILp\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(functio" ascii
    $s2  = "(function fuck(){return \"MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){r" ascii
    $s3  = "){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"DWe\";}" ascii
    $s4  = "eturn \"Za\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\";})()" ascii
    $s5  = "tion fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return" ascii
    $s6  = " \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(fun" ascii
    $s7  = ";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(function f" ascii
    $s8  = "n \"Zy\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(func" ascii
    $s9  = " fuck(){return \"Ve\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"I" ascii
    $s10 = "(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Wo0\";})(),(function fuck" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}