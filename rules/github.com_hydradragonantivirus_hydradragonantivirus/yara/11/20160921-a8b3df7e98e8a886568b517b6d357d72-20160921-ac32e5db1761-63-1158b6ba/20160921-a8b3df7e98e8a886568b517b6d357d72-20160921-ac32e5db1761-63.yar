rule _20160921_a8b3df7e98e8a886568b517b6d357d72_20160921_ac32e5db1761_63 {
  meta:
    description = "datamaliciousorder - from files 20160921_a8b3df7e98e8a886568b517b6d357d72.js, 20160921_ac32e5db1761db7bcee12f6443e4be71.js, 20160921_b9eadd20f28216849138290cb6dac4de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0652be8fe8ee502a5c45d7c0d1b7f5ea93bd8633350801afbb4709b88afc93e2"
    hash2       = "c720e572402df240156cf5af93a10b135edc995ca3aaedbfe6a9673216f7c930"
    hash3       = "4859166acfe74b9a623acc55b045aff7a4c46e4f5c457bb304c5169c6e7fb4a9"

  strings:
    $s1  = "n fuck(){return \"Np\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IP" ascii
    $s2  = ",(function fuck(){return \"DRx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"XFd\";})(),(function fuck()" ascii
    $s3  = "Rx\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"AUx\";})(),(functio" ascii
    $s4  = "tion fuck(){return \"IOs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s5  = "eturn \"To\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"USf\";})()," ascii
    $s6  = "urn \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"PDf\";})(),(" ascii
    $s7  = "tion fuck(){return \"AUx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return" ascii
    $s8  = "(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Fv\";" ascii
    $s9  = "\"XHj\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii
    $s10 = "ction fuck(){return \"RAi\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){retur" ascii
    $s11 = "TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Py\";})(),(functio" ascii
    $s12 = "f\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Qh\";})(),(function" ascii
    $s13 = "uck(){return \"Qh\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg" ascii
    $s14 = "on fuck(){return \"DRx\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return " ascii
    $s15 = "return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"CTm\";})(" ascii
    $s16 = "){return \"ADy\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";}" ascii
    $s17 = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){retur" ascii
    $s18 = "n \"MUs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Cd\";})(),(fu" ascii
    $s19 = "(){return \"Xw\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"MUs\";}" ascii
    $s20 = ")(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ik\";})(),(function fuck" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}