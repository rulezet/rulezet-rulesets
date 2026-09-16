rule _20160921_03b650867a3952f7709688e58e8232f3_20160921_336aeb1d023b_3208 {
  meta:
    description = "datamaliciousorder - from files 20160921_03b650867a3952f7709688e58e8232f3.js, 20160921_336aeb1d023bcb845a70471edfe8a8f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a775853212fe6663d7c077a64c0d4c851d4b7f261a6c0846b4552b556e12a5fe"
    hash2       = "f77fe3497bb26b47e909d597cb0055c997e8149b22c878594ee85d0303c27381"

  strings:
    $s1 = "fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"LG" ascii
    $s2 = "eturn \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})()" ascii
    $s3 = "rn \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(f" ascii
    $s4 = "unction fuck(){return \"OQr\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){ret" ascii
    $s5 = "on fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii
    $s6 = "k(){return \"IOs\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"QTc\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}