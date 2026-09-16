rule _20160921_29f559624390fcbd3c9f89ef4a0d5e1d_20160921_c38068bdcf61_615 {
  meta:
    description = "datamaliciousorder - from files 20160921_29f559624390fcbd3c9f89ef4a0d5e1d.js, 20160921_c38068bdcf6149dc68d38cbcccfe991f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c15ee6fcf772accd2bb85369b8381c6c2cefb7139e589532becec07720a57867"
    hash2       = "d59dd40562ac50a453dbb7054114c62cfd7c63d24b81c776b35af40fb9aa3480"

  strings:
    $s1  = "nction fuck(){return \"Xg\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){retur" ascii
    $s2  = "eturn \"IOs\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(" ascii
    $s3  = "return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(" ascii
    $s4  = "ction fuck(){return \"XFd\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){retu" ascii
    $s5  = "{return \"Za\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})" ascii
    $s6  = "on fuck(){return \"IPu\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return " ascii
    $s7  = "uck(){return \"Dc\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"ZWu" ascii
    $s8  = "fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Yk" ascii
    $s9  = "on fuck(){return \"Vf\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return " ascii
    $s10 = "unction fuck(){return \"IRn\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){re" ascii
    $s11 = "ion fuck(){return \"Ik\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return " ascii
    $s12 = "n \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Na\";})(),(fun" ascii
    $s13 = "(function fuck(){return \"YAv\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){" ascii
    $s14 = "eturn \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Jo\";})()," ascii
    $s15 = "n fuck(){return \"Jo\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"I" ascii
    $s16 = "r\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"YAv\";})(),(function" ascii
    $s17 = "Ik\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(functio" ascii
    $s18 = "ck(){return \"Yk\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Qh\";" ascii
    $s19 = "ction fuck(){return \"Zy\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s20 = "Yk\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Np\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}