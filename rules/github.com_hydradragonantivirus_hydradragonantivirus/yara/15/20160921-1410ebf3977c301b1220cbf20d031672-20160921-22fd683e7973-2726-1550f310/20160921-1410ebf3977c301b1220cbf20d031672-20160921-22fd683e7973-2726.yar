rule _20160921_1410ebf3977c301b1220cbf20d031672_20160921_22fd683e7973_2726 {
  meta:
    description = "datamaliciousorder - from files 20160921_1410ebf3977c301b1220cbf20d031672.js, 20160921_22fd683e7973fc938e9d6980e5e81789.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bba6a8e474a809cf21b57641f08c798b1175b5bb510dcebc8d2284017c4579ab"
    hash2       = "c3583ada9b0a35137add948ee4bd3182a5f977a0dbcc3a39c01ee288f703d566"

  strings:
    $s1 = "rn \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Qh\";})(),(fun" ascii
    $s2 = "function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){re" ascii
    $s3 = "turn \"Zy\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"DRx\";})(),(" ascii
    $s4 = "{return \"XHj\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})" ascii
    $s5 = "(){return \"SUi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\"" ascii
    $s6 = "ck(){return \"XFd\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii
    $s7 = "function fuck(){return \"Oh\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}