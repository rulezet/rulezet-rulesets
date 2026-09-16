rule _20160921_04a7baf184ab1caa54d856e4156daee5_20160921_694d4629e99f_1098 {
  meta:
    description = "datamaliciousorder - from files 20160921_04a7baf184ab1caa54d856e4156daee5.js, 20160921_694d4629e99fd1d23d60bc73e0e28e30.js, 20160921_7f6803f2f6f680d96e6355ff22eeb754.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "436cacbd20422493740457b774290fc75ea097813018720a8afa8162bb912052"
    hash2       = "01147c2f2f43df58f5a1b60481a04add7d73eba030abaeed3f9dedb1fd3574e4"
    hash3       = "90a92dcfba596004523ed3fa83de824553929a4a3723ce68cfae6d2394ad8394"

  strings:
    $s1  = "turn \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"MOj\";})(),(" ascii
    $s2  = "urn \"Np\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Za\";})(),(fu" ascii
    $s3  = "(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"KVh\";})(),(function fuck()" ascii
    $s4  = "\"Oh\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MOj\";})(),(funct" ascii
    $s5  = " \"ZVi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Nm\";})(),(func" ascii
    $s6  = "function fuck(){return \"Na\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){re" ascii
    $s7  = "tion fuck(){return \"Zy\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return " ascii
    $s8  = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){retu" ascii
    $s9  = "Ai\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IRn\";})(),(functio" ascii
    $s10 = "n fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"ILp\";})(),(function fuck(){return " ascii
    $s11 = "function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){re" ascii
    $s12 = "rn \"Oh\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s13 = "on fuck(){return \"TTs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"" ascii
    $s14 = "Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MOj\";})(),(functi" ascii
    $s15 = "n \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"MOj\";})(),(fu" ascii
    $s16 = "on fuck(){return \"Yk\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return " ascii
    $s17 = "ck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"XHj" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}