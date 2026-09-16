rule _20160921_acea633b73985995ce9764bf94db0972_20160921_fec97a223836_970 {
  meta:
    description = "datamaliciousorder - from files 20160921_acea633b73985995ce9764bf94db0972.js, 20160921_fec97a223836973c5d09ac6d41b2ad43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd77df78b3a755b016a27bbcac8fe7c015ab04472e2ca2d2d9aa476befb3148a"
    hash2       = "d8c26b92e119ca52cb4c0aa43351cde4400c3d6abac819e57a391628e14280cb"

  strings:
    $s1  = "})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii
    $s2  = "){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IPu\";}" ascii
    $s3  = "ion fuck(){return \"MIl\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return" ascii
    $s4  = "})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"LGo\";})(),(function fu" ascii
    $s5  = "return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"USf\";})" ascii
    $s6  = "(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"ADy\";})(),(function fuck" ascii
    $s7  = "r\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Dc\";})(),(function f" ascii
    $s8  = "(){return \"OQr\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"FJs\";" ascii
    $s9  = " fuck(){return \"PDf\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"" ascii
    $s10 = "){return \"We\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IRn\";})" ascii
    $s11 = "),(function fuck(){return \"DRx\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(" ascii
    $s12 = " \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Jh\";})(),(func" ascii
    $s13 = "tion fuck(){return \"MBg\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return" ascii
    $s14 = "eturn \"DRx\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Na\";})(),(" ascii
    $s15 = "k(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"YAv\"" ascii
    $s16 = "fuck(){return \"Cd\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu" ascii
    $s17 = " fuck(){return \"DRx\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"G" ascii
    $s18 = "fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Vf" ascii
    $s19 = "turn \"PDf\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Ik\";})(),(f" ascii
    $s20 = "DAa\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}