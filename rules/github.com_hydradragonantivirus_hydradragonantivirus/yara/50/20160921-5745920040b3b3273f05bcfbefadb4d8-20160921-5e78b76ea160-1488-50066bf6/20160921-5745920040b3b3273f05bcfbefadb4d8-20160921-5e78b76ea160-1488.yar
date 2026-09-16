rule _20160921_5745920040b3b3273f05bcfbefadb4d8_20160921_5e78b76ea160_1488 {
  meta:
    description = "datamaliciousorder - from files 20160921_5745920040b3b3273f05bcfbefadb4d8.js, 20160921_5e78b76ea160d891abcb41db9983d51f.js, 20160921_eda7773555acd8e0be7f4e8bf6d0b010.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86b6dab46ebbd6ed243e73b97070b8a7b74178533a419d7a22c3842a74574534"
    hash2       = "789149d5f226f5eb3642909acb465b5f94d946ee53a79d693b40f83359c4471f"
    hash3       = "af4e0a7c109ffa140c9db57a44bcd9c5d9b5a7c75daded0b422d2cec24c01c8b"

  strings:
    $s1  = "rn \"Nm\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Xw\";})(),(func" ascii
    $s2  = "return \"DWe\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Na\";})()" ascii
    $s3  = "(function fuck(){return \"DWe\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){" ascii
    $s4  = "(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"QTc\";" ascii
    $s5  = "),(function fuck(){return \"Yk\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){" ascii
    $s6  = "uck(){return \"Ik\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jh\"" ascii
    $s7  = "tion fuck(){return \"DWe\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return" ascii
    $s8  = "on fuck(){return \"DWe\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return " ascii
    $s9  = "IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Ik\";})(),(functio" ascii
    $s10 = "ck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"AUx" ascii
    $s11 = "ck(){return \"DWe\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz" ascii
    $s12 = "(function fuck(){return \"Ot\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){re" ascii
    $s13 = "o\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}