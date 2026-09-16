rule _20160921_03b650867a3952f7709688e58e8232f3_20160921_11c4976357ef_3209 {
  meta:
    description = "datamaliciousorder - from files 20160921_03b650867a3952f7709688e58e8232f3.js, 20160921_11c4976357ef8a651d058575507518ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a775853212fe6663d7c077a64c0d4c851d4b7f261a6c0846b4552b556e12a5fe"
    hash2       = "aee597813bd24d68729b505b5e718b120274cb1db588f64e61c1a4eb85f6bf11"

  strings:
    $s1 = "return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(" ascii
    $s2 = "e\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"OPz\";})(),(function" ascii
    $s3 = "nction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){retur" ascii
    $s4 = "k(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"XCr" ascii
    $s5 = "(){return \"Nm\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IRn\";}" ascii
    $s6 = "function fuck(){return \"Vf\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}