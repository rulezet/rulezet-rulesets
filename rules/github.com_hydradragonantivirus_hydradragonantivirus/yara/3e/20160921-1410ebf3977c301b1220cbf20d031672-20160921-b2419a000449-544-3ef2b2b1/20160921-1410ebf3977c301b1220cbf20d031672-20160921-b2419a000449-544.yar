rule _20160921_1410ebf3977c301b1220cbf20d031672_20160921_b2419a000449_544 {
  meta:
    description = "datamaliciousorder - from files 20160921_1410ebf3977c301b1220cbf20d031672.js, 20160921_b2419a000449b12cbd6aff3732baf55d.js, 20160921_cb95437e5f7b0cd43bdbd6381ee6a105.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bba6a8e474a809cf21b57641f08c798b1175b5bb510dcebc8d2284017c4579ab"
    hash2       = "ea7b5520c177b4adf74565706c3c8ed38eed94f30b6927b0ceb647f7f768a2b5"
    hash3       = "46d771acb80357bcbb0857af9e7a4a35304fdbbf9785ec02f88f92f1268dfa71"

  strings:
    $s1  = "(){return \"MUs\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Mw\";}" ascii
    $s2  = "tion fuck(){return \"We\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s3  = "tion fuck(){return \"Oh\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return " ascii
    $s4  = "ction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return" ascii
    $s5  = " \"XCr\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s6  = "uck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Cd" ascii
    $s7  = "on fuck(){return \"Pc\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"" ascii
    $s8  = "\"To\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(functi" ascii
    $s9  = "(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ik\";}" ascii
    $s10 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){ret" ascii
    $s11 = "k(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"USf\";}" ascii
    $s12 = "rn \"Wn\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ar\";})(),(func" ascii
    $s13 = "urn \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s14 = "{return \"Jh\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s15 = "turn \"YAv\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})()" ascii
    $s16 = "nction fuck(){return \"Wo0\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){retu" ascii
    $s17 = "nction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){retu" ascii
    $s18 = " \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"UXf\";})(),(fun" ascii
    $s19 = "\"Qh\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(functi" ascii
    $s20 = "fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"CC" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}