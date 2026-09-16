rule _20160921_766f6fcbd2a94a55747a3f5b9a204b0e_20160921_ccb7f2594ec3_1604 {
  meta:
    description = "datamaliciousorder - from files 20160921_766f6fcbd2a94a55747a3f5b9a204b0e.js, 20160921_ccb7f2594ec30d819d8973993796faf6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ac34bd929ce60a874936fef08adcce78783c70441a9eff1cd392604bcf45ff7"
    hash2       = "d05110dd6f0ccc6122f08dac231858be0e233eb3cfb596f5f571556d227ab3ef"

  strings:
    $s1  = "return \"Zy\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s2  = "uck(){return \"XFd\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu" ascii
    $s3  = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){re" ascii
    $s4  = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){retur" ascii
    $s5  = " \"KVh\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\";})(),(fu" ascii
    $s6  = "n fuck(){return \"PDf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s7  = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"" ascii
    $s8  = "rn \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"GNm\";})(),(fu" ascii
    $s9  = "rn \"MIl\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s10 = "(){return \"Nm\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})" ascii
    $s11 = ",(function fuck(){return \"DWe\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){" ascii
    $s12 = "ck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"NKq\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}