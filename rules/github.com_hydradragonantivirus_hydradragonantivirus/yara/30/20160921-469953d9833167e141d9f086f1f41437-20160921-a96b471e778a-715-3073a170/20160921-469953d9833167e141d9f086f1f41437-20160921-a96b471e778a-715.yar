rule _20160921_469953d9833167e141d9f086f1f41437_20160921_a96b471e778a_715 {
  meta:
    description = "datamaliciousorder - from files 20160921_469953d9833167e141d9f086f1f41437.js, 20160921_a96b471e778a8101c168e06727d930fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e29808d818b8f5ea60d0baa8d6c3284d3673878f7f4309c5981ced86dc40c5f1"
    hash2       = "f39378ed9c109b442c660bd7c383f0420860e3ac084eca6bb2fd789ead573a49"

  strings:
    $s1  = ";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"MOj\";})(),(function fuc" ascii
    $s2  = " \"Ar\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"CCb\";})(),(funct" ascii
    $s3  = "\"IPu\";})(),(function fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(func" ascii
    $s4  = "n \"MUs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Qh\";})(),(fu" ascii
    $s5  = "\"IPu\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(func" ascii
    $s6  = "\"NKq\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Ug\";})(),(func" ascii
    $s7  = "unction fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){ret" ascii
    $s8  = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){retur" ascii
    $s9  = "function fuck(){return \"IOs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){r" ascii
    $s10 = "Qt\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cs\";})(),(function fuck(){return \"Cs\";})(),(function" ascii
    $s11 = "\"Zy\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(funct" ascii
    $s12 = "Qr\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"YQt\";})(),(functio" ascii
    $s13 = "ction fuck(){return \"DWe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){retu" ascii
    $s14 = "uck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu" ascii
    $s15 = " fuck(){return \"CTm\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Dc" ascii
    $s16 = "tion fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return" ascii
    $s17 = "u\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(function " ascii
    $s18 = "fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"I" ascii
    $s19 = "){return \"Hs\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})" ascii
    $s20 = "{return \"Ve\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"USf\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}