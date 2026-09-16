rule _20160921_03b650867a3952f7709688e58e8232f3_20160921_ec2d2710e921_161 {
  meta:
    description = "datamaliciousorder - from files 20160921_03b650867a3952f7709688e58e8232f3.js, 20160921_ec2d2710e9217c2f295a4b410a623d5d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a775853212fe6663d7c077a64c0d4c851d4b7f261a6c0846b4552b556e12a5fe"
    hash2       = "efabdabbb3a7d8e1d713826868acadadd9ab03b4cb57f3799d6add11f212fdd9"

  strings:
    $s1  = "rn \"Xg\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Av\";})(),(fun" ascii
    $s2  = "rn \"GJx\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(" ascii
    $s3  = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"PDf\";})(),(function " ascii
    $s4  = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){retur" ascii
    $s5  = "),(function fuck(){return \"Fv\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){" ascii
    $s6  = "(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Xw\";})(),(function fuck()" ascii
    $s7  = "Zy\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s8  = "ction fuck(){return \"VMi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return" ascii
    $s9  = "\"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Mw\";})(),(funct" ascii
    $s10 = "(function fuck(){return \"We\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){re" ascii
    $s11 = "urn \"XCr\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s12 = "fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Ug" ascii
    $s13 = " \"Py\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(func" ascii
    $s14 = "IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Jg\";})(),(functio" ascii
    $s15 = "tion fuck(){return \"Za\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s16 = "(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Wo0\";}" ascii
    $s17 = "u\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Za\";})(),(function f" ascii
    $s18 = ")(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"LGo\";})(),(function fuck(" ascii
    $s19 = "fuck(){return \"ZLd\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Xw" ascii
    $s20 = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Cd\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}