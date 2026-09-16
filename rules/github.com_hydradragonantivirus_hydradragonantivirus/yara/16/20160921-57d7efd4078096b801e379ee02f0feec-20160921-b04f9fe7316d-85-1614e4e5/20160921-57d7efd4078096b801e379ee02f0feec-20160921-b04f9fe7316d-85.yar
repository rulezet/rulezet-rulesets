rule _20160921_57d7efd4078096b801e379ee02f0feec_20160921_b04f9fe7316d_85 {
  meta:
    description = "datamaliciousorder - from files 20160921_57d7efd4078096b801e379ee02f0feec.js, 20160921_b04f9fe7316d0e86c0046e130e905e37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e568760a55d343665c530313749711c3424bfd35c792b1a8b1d5ad6fa004c9a6"
    hash2       = "58df336ac7568c9f52fedec5d0b900480491f3e65f56c23426010ec745a6bddd"

  strings:
    $s1  = "})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii
    $s2  = ";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuc" ascii
    $s3  = "return \"Py\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Ot\";})()" ascii
    $s4  = "function fuck(){return \"XFd\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){re" ascii
    $s5  = "n fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return " ascii
    $s6  = "n \"PDf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s7  = "\"DRx\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"GNm\";})(),(func" ascii
    $s8  = ")(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"IPu\";})(),(function fuck" ascii
    $s9  = "fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"U" ascii
    $s10 = "\"SUi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(func" ascii
    $s11 = "UXf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(functi" ascii
    $s12 = "eturn \"MBg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})()" ascii
    $s13 = "\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"USf\";})(),(function " ascii
    $s14 = "\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Cd\";})(),(function fu" ascii
    $s15 = "){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"Ml\";})" ascii
    $s16 = "return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ve\";})()" ascii
    $s17 = "(){return \"We\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MOj\";" ascii
    $s18 = ";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"USf\";})(),(function fu" ascii
    $s19 = "(),(function fuck(){return \"We\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(" ascii
    $s20 = "turn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Zy\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}