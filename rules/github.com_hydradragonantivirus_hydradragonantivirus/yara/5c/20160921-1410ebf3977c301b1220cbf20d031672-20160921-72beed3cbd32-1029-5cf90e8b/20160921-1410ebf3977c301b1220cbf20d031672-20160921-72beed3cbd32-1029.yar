rule _20160921_1410ebf3977c301b1220cbf20d031672_20160921_72beed3cbd32_1029 {
  meta:
    description = "datamaliciousorder - from files 20160921_1410ebf3977c301b1220cbf20d031672.js, 20160921_72beed3cbd321b62d224a35a01639682.js, 20160921_f1bb498dcbb1f3aecbc35886be394f58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bba6a8e474a809cf21b57641f08c798b1175b5bb510dcebc8d2284017c4579ab"
    hash2       = "ce3c3a93d2e5df0f850da4d79a5f697eaff66f1043058d62f80adad98b476839"
    hash3       = "486454370a5dac6af41bfda9ac339e37120334ce5f7c4319bd0f8e9df9514b44"

  strings:
    $s1  = "fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Y" ascii
    $s2  = "){return \"Ve\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})" ascii
    $s3  = "eturn \"IOs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s4  = "nction fuck(){return \"DAa\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){ret" ascii
    $s5  = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){retur" ascii
    $s6  = "ion fuck(){return \"Yk\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return " ascii
    $s7  = "fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"SUi" ascii
    $s8  = ",(function fuck(){return \"AUx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck()" ascii
    $s9  = ";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fu" ascii
    $s10 = "return \"Wo0\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})" ascii
    $s11 = "n \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"We\";})(),(fun" ascii
    $s12 = "k(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Nm\";" ascii
    $s13 = "(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"To\";})(),(function fuck(" ascii
    $s14 = "tion fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){retur" ascii
    $s15 = "return \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})" ascii
    $s16 = "Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ot\";})(),(functio" ascii
    $s17 = " \"Vf\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s18 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}