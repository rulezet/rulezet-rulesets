rule _20160921_0344ac0ed807ef595e2aeca98d44f575_20160921_5e78b76ea160_1764 {
  meta:
    description = "datamaliciousorder - from files 20160921_0344ac0ed807ef595e2aeca98d44f575.js, 20160921_5e78b76ea160d891abcb41db9983d51f.js, 20160921_eda7773555acd8e0be7f4e8bf6d0b010.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f631e328f07a7c3d34221081061f64d96da25c4f05169c427adb507bb6941f58"
    hash2       = "789149d5f226f5eb3642909acb465b5f94d946ee53a79d693b40f83359c4471f"
    hash3       = "af4e0a7c109ffa140c9db57a44bcd9c5d9b5a7c75daded0b422d2cec24c01c8b"

  strings:
    $s1  = "DWe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(funct" ascii
    $s2  = "})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"DRx\";})(),(function fuck" ascii
    $s3  = "k(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Cd\"" ascii
    $s4  = "(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){r" ascii
    $s5  = "tion fuck(){return \"Ik\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return " ascii
    $s6  = " fuck(){return \"Et\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DR" ascii
    $s7  = "ck(){return \"TTs\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Av\";" ascii
    $s8  = "urn \"ZWu\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"DRx\";})(),(" ascii
    $s9  = "k\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s10 = ",(function fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"DWe\";})(),(function fuck()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}