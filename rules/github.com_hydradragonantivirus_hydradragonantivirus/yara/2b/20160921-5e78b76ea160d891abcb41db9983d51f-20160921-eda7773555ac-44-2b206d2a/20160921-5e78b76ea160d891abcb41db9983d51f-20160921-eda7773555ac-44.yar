rule _20160921_5e78b76ea160d891abcb41db9983d51f_20160921_eda7773555ac_44 {
  meta:
    description = "datamaliciousorder - from files 20160921_5e78b76ea160d891abcb41db9983d51f.js, 20160921_eda7773555acd8e0be7f4e8bf6d0b010.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "789149d5f226f5eb3642909acb465b5f94d946ee53a79d693b40f83359c4471f"
    hash2       = "af4e0a7c109ffa140c9db57a44bcd9c5d9b5a7c75daded0b422d2cec24c01c8b"

  strings:
    $s1  = "ion fuck(){return \"Qh\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return " ascii
    $s2  = "rn \"GJx\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"LGo\";})(),(" ascii
    $s3  = ")(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii
    $s4  = "tion fuck(){return \"Vb\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return " ascii
    $s5  = "Rn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Xg\";})(),(functio" ascii
    $s6  = " \"TTs\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Ik\";})(),(funct" ascii
    $s7  = "turn \"MIl\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()," ascii
    $s8  = "n \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"DWe\";})(),(fu" ascii
    $s9  = " fuck(){return \"DWe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"" ascii
    $s10 = "\"DWe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s11 = "nction fuck(){return \"USf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){retur" ascii
    $s12 = "uck(){return \"ZWu\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn" ascii
    $s13 = "(function fuck(){return \"Cd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){r" ascii
    $s14 = "tion fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){retur" ascii
    $s15 = "ction fuck(){return \"XHj\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){retu" ascii
    $s16 = "(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"IRn\";})(),(function fuck" ascii
    $s17 = "k(){return \"IPu\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Py\";}" ascii
    $s18 = "XCr\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"UOe\";})(),(functio" ascii
    $s19 = "(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Xw\";})(),(function fuck()" ascii
    $s20 = "tion fuck(){return \"Cs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}