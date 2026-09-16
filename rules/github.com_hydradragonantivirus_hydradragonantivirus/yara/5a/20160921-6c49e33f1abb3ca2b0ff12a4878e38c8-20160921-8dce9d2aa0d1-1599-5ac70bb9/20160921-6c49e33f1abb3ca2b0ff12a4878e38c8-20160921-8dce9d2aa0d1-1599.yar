rule _20160921_6c49e33f1abb3ca2b0ff12a4878e38c8_20160921_8dce9d2aa0d1_1599 {
  meta:
    description = "datamaliciousorder - from files 20160921_6c49e33f1abb3ca2b0ff12a4878e38c8.js, 20160921_8dce9d2aa0d1e296bbcc31a437e35a45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2c5f6e5a1ebce2cb0eb54f0d28ea21ab88b07dc646376bb3fc5ce29af1615aa"
    hash2       = "26c784fc7a8e4ee1608e66a82f1ba134972418c5968433b39f54392e7f3de0f2"

  strings:
    $s1  = "(){return \"TTs\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IPu\"" ascii
    $s2  = "return \"Zy\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(" ascii
    $s3  = "tion fuck(){return \"Qh\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return " ascii
    $s4  = "nction fuck(){return \"Sx\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s5  = "(){return \"Jg\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XFd\";" ascii
    $s6  = "Jo\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(functi" ascii
    $s7  = "Yk\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"MIl\";})(),(functi" ascii
    $s8  = "ction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){retur" ascii
    $s9  = "ion fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return " ascii
    $s10 = "){return \"TTs\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";}" ascii
    $s11 = "x\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"YQt\";})(),(function" ascii
    $s12 = "rn \"PDf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Hs\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}