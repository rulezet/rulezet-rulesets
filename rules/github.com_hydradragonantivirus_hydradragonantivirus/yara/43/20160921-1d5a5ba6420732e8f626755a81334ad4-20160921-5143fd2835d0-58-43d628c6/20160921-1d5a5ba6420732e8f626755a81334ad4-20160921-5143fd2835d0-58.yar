rule _20160921_1d5a5ba6420732e8f626755a81334ad4_20160921_5143fd2835d0_58 {
  meta:
    description = "datamaliciousorder - from files 20160921_1d5a5ba6420732e8f626755a81334ad4.js, 20160921_5143fd2835d058f3854ef7b166166de4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47a1fbd3f8785b259468283f9d6611b34da6b0170d66a933ade09c56548f89b4"
    hash2       = "0824c6197846b6efc3bea2626d4bc5983302ec11dd40189770e6572811d3d42c"

  strings:
    $s1  = "turn \"CCb\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"MOj\";})()" ascii
    $s2  = "rn \"Xw\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Xw\";})(),(fu" ascii
    $s3  = "){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";}" ascii
    $s4  = " fuck(){return \"PDf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"I" ascii
    $s5  = "rn \"Zy\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(fun" ascii
    $s6  = "})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(" ascii
    $s7  = "){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Cd\";})(" ascii
    $s8  = "ion fuck(){return \"MBg\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return" ascii
    $s9  = "n fuck(){return \"Ar\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"" ascii
    $s10 = "{return \"Wo0\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})" ascii
    $s11 = "IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"YAv\";})(),(functio" ascii
    $s12 = "ck(){return \"Qh\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn" ascii
    $s13 = "g\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Mw\";})(),(function " ascii
    $s14 = "k(){return \"Zy\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";" ascii
    $s15 = "nction fuck(){return \"PDf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){ret" ascii
    $s16 = " fuck(){return \"Oh\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IP" ascii
    $s17 = " \"We\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s18 = " fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Az\";})(),(function fuck(){return \"Xw" ascii
    $s19 = "\"RAi\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(func" ascii
    $s20 = "ck(){return \"UXf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}