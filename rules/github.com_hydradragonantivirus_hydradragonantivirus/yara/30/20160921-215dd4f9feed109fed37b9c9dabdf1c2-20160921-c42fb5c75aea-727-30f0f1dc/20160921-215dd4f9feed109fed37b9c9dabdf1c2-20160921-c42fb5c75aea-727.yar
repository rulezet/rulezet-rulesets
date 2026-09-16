rule _20160921_215dd4f9feed109fed37b9c9dabdf1c2_20160921_c42fb5c75aea_727 {
  meta:
    description = "datamaliciousorder - from files 20160921_215dd4f9feed109fed37b9c9dabdf1c2.js, 20160921_c42fb5c75aea2648513013ad2eed9aaf.js, 20160921_dc1ff053e9dd688459c33dc98e88d636.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "710f88c7fda95a8d3e0e04de1ffd81606d227d249d76eb0d7fbeba7a0284a86e"
    hash2       = "5c8cdf3dbb94e197c36e5744084d12e198ecdab7243d67654934aa1cc9bf7ae9"
    hash3       = "18a890096a5714e518b28d3f50f6487cfbc4164418daae1842b7d724e2c26bd6"

  strings:
    $s1  = "return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Sx\";})(" ascii
    $s2  = "on fuck(){return \"Ot\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return " ascii
    $s3  = "ck(){return \"Vb\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";" ascii
    $s4  = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return" ascii
    $s5  = "turn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Sx\";})(),(" ascii
    $s6  = "uck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ve" ascii
    $s7  = ",(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){" ascii
    $s8  = "u\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"YAv\";})(),(function" ascii
    $s9  = "ck(){return \"XHj\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii
    $s10 = "(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Et\";" ascii
    $s11 = ")(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Nm\";})(),(function fuck(" ascii
    $s12 = "urn \"Ug\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Jo\";})(),(fu" ascii
    $s13 = "Ve\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"DRx\";})(),(functio" ascii
    $s14 = "){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";}" ascii
    $s15 = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Ug\";})(),(function fuck" ascii
    $s16 = "){return \"IPu\";})(),(function fuck(){return \"LLv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";}" ascii
    $s17 = "Aa\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(functi" ascii
    $s18 = "rn \"Wo\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(f" ascii
    $s19 = "s\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(functio" ascii
    $s20 = "Fv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}