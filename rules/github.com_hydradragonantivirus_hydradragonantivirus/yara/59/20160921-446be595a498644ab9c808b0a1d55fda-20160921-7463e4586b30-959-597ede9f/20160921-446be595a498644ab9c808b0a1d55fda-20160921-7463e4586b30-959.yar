rule _20160921_446be595a498644ab9c808b0a1d55fda_20160921_7463e4586b30_959 {
  meta:
    description = "datamaliciousorder - from files 20160921_446be595a498644ab9c808b0a1d55fda.js, 20160921_7463e4586b309c15d7048a37c63c1226.js, 20160921_87ced6523e47b3b752b2353107bc989a.js, 20160921_945a46518061bd8e157aed251e0ffa9e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "735df5a75dd8a8fa643384cdee60651aafaebc84d57deefb035eb570ba25a521"
    hash2       = "96a40a72711934aeffde8b64056102f9e3de80fa22eecc0a25cf9c045d3ab190"
    hash3       = "46c521beb23d37cfa4d60cfcab38c941734971fe3102123b7e4c2813544d39b6"
    hash4       = "cc3d236edb3b45a767b438fa21243a07176d6f5def724e03e45aca76b3127054"

  strings:
    $s1  = "unction fuck(){return \"Vb\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){retur" ascii
    $s2  = "nction fuck(){return \"Jh\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){retu" ascii
    $s3  = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return" ascii
    $s4  = "{return \"DAa\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";}" ascii
    $s5  = "(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(" ascii
    $s6  = "Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Cd\";})(),(functio" ascii
    $s7  = "function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){ret" ascii
    $s8  = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Ug\";})(),(function fuc" ascii
    $s9  = "n \"Ot\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Jo\";})(),(fun" ascii
    $s10 = "k(){return \"Ai\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\"" ascii
    $s11 = "DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Nm\";})(),(functi" ascii
    $s12 = " \"GJx\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Np\";})(),(func" ascii
    $s13 = "rn \"OQr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"FJs\";})(),(f" ascii
    $s14 = "){return \"Fv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})" ascii
    $s15 = "Cr\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(functi" ascii
    $s16 = "function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){re" ascii
    $s17 = "(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(" ascii
    $s18 = "),(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){" ascii
    $s19 = "turn \"UXf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Nm\";})(),(" ascii
    $s20 = "return \"Nm\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}