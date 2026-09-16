rule _20160921_a8b3df7e98e8a886568b517b6d357d72_20160921_ac32e5db1761_639 {
  meta:
    description = "datamaliciousorder - from files 20160921_a8b3df7e98e8a886568b517b6d357d72.js, 20160921_ac32e5db1761db7bcee12f6443e4be71.js, 20160921_ad0fbcfca87e48302530672c4ceab093.js, 20160921_b9eadd20f28216849138290cb6dac4de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0652be8fe8ee502a5c45d7c0d1b7f5ea93bd8633350801afbb4709b88afc93e2"
    hash2       = "c720e572402df240156cf5af93a10b135edc995ca3aaedbfe6a9673216f7c930"
    hash3       = "481451a3850055fd2d398d5707171f67d2aa3cd019214d6b67f539efc81ca7bb"
    hash4       = "4859166acfe74b9a623acc55b045aff7a4c46e4f5c457bb304c5169c6e7fb4a9"

  strings:
    $s1  = " \"TTs\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Hs\";})(),(func" ascii
    $s2  = "fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Fv" ascii
    $s3  = "fuck(){return \"Np\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Za" ascii
    $s4  = "Tv\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Na\";})(),(function " ascii
    $s5  = "eturn \"YQt\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IRn\";})()" ascii
    $s6  = "nction fuck(){return \"PDf\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Za\";})(),(function fuck(){retu" ascii
    $s7  = "n \"DRx\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s8  = "turn \"Yk\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()," ascii
    $s9  = "unction fuck(){return \"Mw\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){ret" ascii
    $s10 = "ction fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s11 = "ck(){return \"Np\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu" ascii
    $s12 = "nction fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){retu" ascii
    $s13 = "tion fuck(){return \"Oh\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return " ascii
    $s14 = "urn \"Ot\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s15 = "(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";}" ascii
    $s16 = "urn \"PDf\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"LGo\";})(),(" ascii
    $s17 = "ck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Jh" ascii
    $s18 = "fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"V" ascii
    $s19 = "tion fuck(){return \"Xg\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return " ascii
    $s20 = "\"Np\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MOj\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}