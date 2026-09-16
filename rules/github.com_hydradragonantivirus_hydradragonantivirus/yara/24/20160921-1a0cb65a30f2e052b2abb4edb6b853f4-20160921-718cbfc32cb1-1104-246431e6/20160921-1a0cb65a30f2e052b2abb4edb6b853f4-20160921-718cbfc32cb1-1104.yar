rule _20160921_1a0cb65a30f2e052b2abb4edb6b853f4_20160921_718cbfc32cb1_1104 {
  meta:
    description = "datamaliciousorder - from files 20160921_1a0cb65a30f2e052b2abb4edb6b853f4.js, 20160921_718cbfc32cb1f435745a5a005d3f190b.js, 20160921_a8c002f684df9aec957f2a082ed80d84.js, 20160921_ba57fd323c757d83bd9bb08cdba3b4a4.js, 20160921_efc4e68608b4bd36f7e16eb4722b21c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb576c42df90a554f241d4a5ba0dee1dfcb9caf661cf46a2800b743aa592e644"
    hash2       = "7611b8615a5a07f89bc6a867e9232ae443f0ff2bb48d960d2254e1390a27fdee"
    hash3       = "9db5f5694048d441a47fe4382700213cc288d4fba152eec7b99fdd310a50ef7d"
    hash4       = "119b312aafd59cd12991442685e391e8850e3417b81d4aa79ae8e5c89a75f170"
    hash5       = "fe50eec4105613d48ac273c2d63a5b952098f339f7f06871b77053c43642dba7"

  strings:
    $s1  = "eturn \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"LGo\";})()" ascii
    $s2  = "{return \"Ai\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s3  = "on fuck(){return \"Cd\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"" ascii
    $s4  = "rn \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XFd\";})(),(f" ascii
    $s5  = "(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cs\";})(),(function fuck(){re" ascii
    $s6  = "Cs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Nm\";})(),(functio" ascii
    $s7  = "tion fuck(){return \"Zy\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return " ascii
    $s8  = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retu" ascii
    $s9  = "fuck(){return \"CCb\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"M" ascii
    $s10 = "We\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"DWe\";})(),(function" ascii
    $s11 = "rn \"Cd\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(fu" ascii
    $s12 = "uck(){return \"CTm\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs" ascii
    $s13 = "\"Yk\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"XHj\";})(),(funct" ascii
    $s14 = "(),(function fuck(){return \"Av\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"We\";})(),(function fuck()" ascii
    $s15 = "k(){return \"Oh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";" ascii
    $s16 = "(function fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){r" ascii
    $s17 = "n \"CCb\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}