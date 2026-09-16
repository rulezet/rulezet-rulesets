rule _20160921_5f040a1454cafc62100cb4449da0b7e2_20160921_5fbbbcb8f403_118 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f040a1454cafc62100cb4449da0b7e2.js, 20160921_5fbbbcb8f403a68df153b90d52e5fff9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ffb0f3f8e3e8ace2b8b6c1bccf53c8b5a11fd2ed00ff3b54971e8b0ca5e139d"
    hash2       = "1e2661f95b6bb745bac719b1313cfa9a489ecd857f66bfe9fe5398391e372ca4"

  strings:
    $s1  = "ction fuck(){return \"Xg\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return" ascii
    $s2  = "unction fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Et\";})(),(function fuck(){ret" ascii
    $s3  = "turn \"XFd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MBg\";})()," ascii
    $s4  = "eturn \"Ar\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Cd\";})(),(" ascii
    $s5  = "fuck(){return \"DRx\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"ZV" ascii
    $s6  = "function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){ret" ascii
    $s7  = "fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw" ascii
    $s8  = "\"GJx\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s9  = "function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){re" ascii
    $s10 = "QTc\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(funct" ascii
    $s11 = " fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"UO" ascii
    $s12 = "){return \"DWe\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";" ascii
    $s13 = "ck(){return \"ZVi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Cd\"" ascii
    $s14 = "on fuck(){return \"Vf\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"" ascii
    $s15 = "(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck()" ascii
    $s16 = "(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){r" ascii
    $s17 = "uck(){return \"Xw\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu" ascii
    $s18 = "{return \"Zy\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})" ascii
    $s19 = "function fuck(){return \"Vf\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s20 = "Hj\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"NKq\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}