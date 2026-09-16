rule _20160921_ae190d4c26ff954cee57fde04839fdcd_20160921_ede755ec6df0_3118 {
  meta:
    description = "datamaliciousorder - from files 20160921_ae190d4c26ff954cee57fde04839fdcd.js, 20160921_ede755ec6df0951d79fb3f792a6b28b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a337ab3ebbd0c762482045ac2f2536c27fbe1276893efdedbafc2c805709064"
    hash2       = "24831eade0fe1d3e87c174bc2c80b113a66f4b5da6235749feba09a377913e7a"

  strings:
    $s1 = "ion fuck(){return \"YQt\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return" ascii
    $s2 = "ck(){return \"Cd\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq" ascii
    $s3 = " fuck(){return \"We\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"LG" ascii
    $s4 = "n \"Vf\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(fun" ascii
    $s5 = "uck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"MUs" ascii
    $s6 = "),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"YQt\";})(),(function fuck()" ascii
    $s7 = "return \"TTs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}