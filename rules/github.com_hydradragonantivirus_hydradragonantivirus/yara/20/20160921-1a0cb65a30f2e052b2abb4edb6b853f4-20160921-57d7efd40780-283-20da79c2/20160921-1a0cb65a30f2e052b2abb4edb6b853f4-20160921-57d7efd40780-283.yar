rule _20160921_1a0cb65a30f2e052b2abb4edb6b853f4_20160921_57d7efd40780_283 {
  meta:
    description = "datamaliciousorder - from files 20160921_1a0cb65a30f2e052b2abb4edb6b853f4.js, 20160921_57d7efd4078096b801e379ee02f0feec.js, 20160921_a8c002f684df9aec957f2a082ed80d84.js, 20160921_b04f9fe7316d0e86c0046e130e905e37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb576c42df90a554f241d4a5ba0dee1dfcb9caf661cf46a2800b743aa592e644"
    hash2       = "e568760a55d343665c530313749711c3424bfd35c792b1a8b1d5ad6fa004c9a6"
    hash3       = "9db5f5694048d441a47fe4382700213cc288d4fba152eec7b99fdd310a50ef7d"
    hash4       = "58df336ac7568c9f52fedec5d0b900480491f3e65f56c23426010ec745a6bddd"

  strings:
    $s1  = "k(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\"" ascii
    $s2  = "Df\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(functio" ascii
    $s3  = "on fuck(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s4  = "rn \"MBg\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"FJs\";})(),(f" ascii
    $s5  = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return" ascii
    $s6  = "on fuck(){return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return " ascii
    $s7  = "return \"ADy\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})()" ascii
    $s8  = "nction fuck(){return \"MBg\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){ret" ascii
    $s9  = "){return \"Cd\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})" ascii
    $s10 = "(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";" ascii
    $s11 = "LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(functio" ascii
    $s12 = " fuck(){return \"TTs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"" ascii
    $s13 = "urn \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s14 = "ck(){return \"ADy\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\"" ascii
    $s15 = "turn \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s16 = "nction fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){ret" ascii
    $s17 = "return \"Tv\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Na\";})()" ascii
    $s18 = "turn \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\";})()" ascii
    $s19 = "fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"L" ascii
    $s20 = "fuck(){return \"TTs\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"I" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}