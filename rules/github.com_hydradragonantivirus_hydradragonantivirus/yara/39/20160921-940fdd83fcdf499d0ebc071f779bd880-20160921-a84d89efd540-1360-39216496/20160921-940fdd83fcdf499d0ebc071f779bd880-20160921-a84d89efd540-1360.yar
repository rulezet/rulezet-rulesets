rule _20160921_940fdd83fcdf499d0ebc071f779bd880_20160921_a84d89efd540_1360 {
  meta:
    description = "datamaliciousorder - from files 20160921_940fdd83fcdf499d0ebc071f779bd880.js, 20160921_a84d89efd5400c906c1132a56b0ef679.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b73c87ed73bc62067299b13aaa227535cbedafa1a7f74ad02273d1aad3a3449f"
    hash2       = "f3cfecdabdf17d9af410d0fee7ec88844bc361668aca1a114832bd3e515d3456"

  strings:
    $s1  = "ck(){return \"Na\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vb\"" ascii
    $s2  = " \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"XHj\";})(),(fun" ascii
    $s3  = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){ret" ascii
    $s4  = "(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"UXf\";})(),(function fuck(" ascii
    $s5  = "return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"SUi\";})" ascii
    $s6  = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){retur" ascii
    $s7  = "turn \"Cd\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s8  = "Dy\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"ZWu\";})(),(functi" ascii
    $s9  = "\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Ik\";})(),(function fu" ascii
    $s10 = "(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MOj\";})(),(function fuck" ascii
    $s11 = "eturn \"TTs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Fv\";})(),(" ascii
    $s12 = "function fuck(){return \"TTs\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Av\";})(),(function fuck(){ret" ascii
    $s13 = "),(function fuck(){return \"Et\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){" ascii
    $s14 = "rn \"Hs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(fu" ascii
    $s15 = "on fuck(){return \"TTs\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}