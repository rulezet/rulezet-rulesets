rule _20160921_511769d99fbe4d59a2e55781fb0eb77c_20160921_d905978b34be_1584 {
  meta:
    description = "datamaliciousorder - from files 20160921_511769d99fbe4d59a2e55781fb0eb77c.js, 20160921_d905978b34bea5948e843dd7ecb9dc6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f4a69b097fb3d0d29d7f041be11cd2e8af137bd0ed525674079a1b7de28c7fd"
    hash2       = "8110e9072a75f1960f23243cc11d3c233a350d63360d8006cad608a2fb81e0b3"

  strings:
    $s1  = "tion fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){retur" ascii
    $s2  = " \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IRn\";})(),(fun" ascii
    $s3  = "\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s4  = "uck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"RAi" ascii
    $s5  = "ck(){return \"Yk\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"XHj\"" ascii
    $s6  = "k(){return \"We\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"DWe\";}" ascii
    $s7  = "return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ZVi\";})" ascii
    $s8  = "ck(){return \"MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf" ascii
    $s9  = "uck(){return \"YAv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GW" ascii
    $s10 = "function fuck(){return \"Jg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){re" ascii
    $s11 = "eturn \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s12 = "tion fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}