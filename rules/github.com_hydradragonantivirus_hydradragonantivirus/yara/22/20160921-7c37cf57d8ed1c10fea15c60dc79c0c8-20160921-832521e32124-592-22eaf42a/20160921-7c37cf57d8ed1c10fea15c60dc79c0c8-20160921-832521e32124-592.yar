rule _20160921_7c37cf57d8ed1c10fea15c60dc79c0c8_20160921_832521e32124_592 {
  meta:
    description = "datamaliciousorder - from files 20160921_7c37cf57d8ed1c10fea15c60dc79c0c8.js, 20160921_832521e32124647e5f9543472346f319.js, 20160921_d44650cb742ce4feede24ebce4407e1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3acecff4ec35ade7d618cbd511372d6023de7d591317c5e6ce95fc088b8cf6e"
    hash2       = "7d8db496c31215a3730a6ed92a0e2b36ff0fe0e9ddaf7405680d1002474263e1"
    hash3       = "5d3f7264c4109728074b6f96ac9910bb0072014149731ab6e6b307d40d5c37ff"

  strings:
    $s1  = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Et\";})(),(function fuck(" ascii
    $s2  = " fuck(){return \"IPu\";})(),(function fuck(){return \"LLv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s3  = " fuck(){return \"Ai\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OP" ascii
    $s4  = "return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s5  = "return \"Sx\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"We\";})()" ascii
    $s6  = "(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(" ascii
    $s7  = "ion fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return" ascii
    $s8  = "n \"Cs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(fu" ascii
    $s9  = ")(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii
    $s10 = "){return \"Yk\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\";}" ascii
    $s11 = "return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(" ascii
    $s12 = "eturn \"Ve\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(" ascii
    $s13 = "unction fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){ret" ascii
    $s14 = ",(function fuck(){return \"Ve\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){r" ascii
    $s15 = "on fuck(){return \"MIl\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s16 = ",(function fuck(){return \"PDf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck()" ascii
    $s17 = "d\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s18 = "tion fuck(){return \"Ar\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return " ascii
    $s19 = "turn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Qh\";})(),(" ascii
    $s20 = "k(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}