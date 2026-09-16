rule _20160921_18f3609106b0af59da0b1200fe14abc1_20160921_615f98dbcc83_726 {
  meta:
    description = "datamaliciousorder - from files 20160921_18f3609106b0af59da0b1200fe14abc1.js, 20160921_615f98dbcc83e57c9789ba9d89e188d0.js, 20160921_e4c63c3b699efd2f5fe2739b016a938a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95fb9e6292746461417b0e539747d500c780ad17cb775a9db031f77eaa53a3e2"
    hash2       = "3ee4da5f56533720f6cb24f55125aadc635f7464c5c8a7fbc14e3949f44d0ee5"
    hash3       = "9d5d6c2986818649619806d890aad49cda8d0da47fe67f38388e5441a53382a0"

  strings:
    $s1  = "ion fuck(){return \"Zy\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return " ascii
    $s2  = "fuck(){return \"Dc\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MB" ascii
    $s3  = "fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"UXf" ascii
    $s4  = "){return \"Wo0\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";}" ascii
    $s5  = "nction fuck(){return \"Hs\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){retu" ascii
    $s6  = "g\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"USf\";})(),(function " ascii
    $s7  = "x\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Jh\";})(),(function" ascii
    $s8  = "on fuck(){return \"Py\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return " ascii
    $s9  = "IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"MBg\";})(),(functi" ascii
    $s10 = "eturn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"XCr\";})(" ascii
    $s11 = "turn \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s12 = ",(function fuck(){return \"DWe\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){" ascii
    $s13 = "o\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"RAi\";})(),(function" ascii
    $s14 = "eturn \"Hs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()," ascii
    $s15 = "rn \"Ot\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Cd\";})(),(fu" ascii
    $s16 = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"We\";})(),(function f" ascii
    $s17 = "urn \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(" ascii
    $s18 = "n fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"" ascii
    $s19 = "return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"UOe\";})(" ascii
    $s20 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}