rule _20160921_50544c5faa56c0c9ed1c35075bafc583_20160921_7f682825ca90_728 {
  meta:
    description = "datamaliciousorder - from files 20160921_50544c5faa56c0c9ed1c35075bafc583.js, 20160921_7f682825ca903be9931443996a6639e7.js, 20160921_f80c41f35464b4c1cc71c3a8431a6e96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "978b707f3e5da0fd4a8e7394863db19802410ff1b96376fc2432de59fafc5a69"
    hash2       = "0702db471409264d1d764fadd3401cdedc4b3ca7166d99d61893fad5007d7f03"
    hash3       = "8186d069d8ec2c8754bba46343500f71eff6d1d47a5ecb2ca82a097bf5b41dc3"

  strings:
    $s1  = "Fd\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"RAi\";})(),(functi" ascii
    $s2  = "return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"YQt\";})(" ascii
    $s3  = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Jo\";})(),(function fuck" ascii
    $s4  = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"GWo\";})(),(function fu" ascii
    $s5  = "(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Za\";})(),(function fuck(){re" ascii
    $s6  = "n fuck(){return \"ZWu\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s7  = ")(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"DRx\";})(),(function fuck" ascii
    $s8  = "fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"AU" ascii
    $s9  = " fuck(){return \"XCr\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"D" ascii
    $s10 = "n fuck(){return \"Et\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"N" ascii
    $s11 = "),(function fuck(){return \"Ve\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"DRx\";})(),(function fuck()" ascii
    $s12 = "Ui\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functi" ascii
    $s13 = "(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"ADy\";" ascii
    $s14 = "nction fuck(){return \"YQt\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s15 = "urn \"Vf\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"DRx\";})(),(" ascii
    $s16 = "eturn \"DRx\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"UXf\";})()" ascii
    $s17 = "Go\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"NKq\";})(),(functi" ascii
    $s18 = "eturn \"PDf\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"RAi\";})()" ascii
    $s19 = "on fuck(){return \"DRx\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return " ascii
    $s20 = "UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Wo\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}