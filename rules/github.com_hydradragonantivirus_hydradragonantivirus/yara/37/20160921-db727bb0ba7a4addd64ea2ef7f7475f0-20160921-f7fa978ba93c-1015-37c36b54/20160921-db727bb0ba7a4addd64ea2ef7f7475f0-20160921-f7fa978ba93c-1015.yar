rule _20160921_db727bb0ba7a4addd64ea2ef7f7475f0_20160921_f7fa978ba93c_1015 {
  meta:
    description = "datamaliciousorder - from files 20160921_db727bb0ba7a4addd64ea2ef7f7475f0.js, 20160921_f7fa978ba93ca4504da33fc02cbf7f53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12f83f9c7412fb362b5d1e9209d11bdf03d66f9505ff4d2247b8a85f687d4cb8"
    hash2       = "8c8d20603b0870465254e9f226f52f020b5b1d986c61571e7a3097b32ea728e0"

  strings:
    $s1  = "ction fuck(){return \"Np\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return" ascii
    $s2  = "function fuck(){return \"OQr\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){re" ascii
    $s3  = "){return \"GWo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";" ascii
    $s4  = "DRx\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Sx\";})(),(functio" ascii
    $s5  = "urn \"MBg\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s6  = "\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"YAv\";})(),(function " ascii
    $s7  = "})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"YQt\";})(),(function fu" ascii
    $s8  = "){return \"ADy\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Mw\";}" ascii
    $s9  = "on fuck(){return \"SUi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return " ascii
    $s10 = "ction fuck(){return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){retur" ascii
    $s11 = "ion fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return " ascii
    $s12 = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){retur" ascii
    $s13 = "turn \"IPu\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})()" ascii
    $s14 = "(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"IRn\";})(),(function fuck" ascii
    $s15 = "(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"LGo\"" ascii
    $s16 = " fuck(){return \"DHd\";})(),(function fuck(){return \"Ml\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"O" ascii
    $s17 = "k(){return \"Oh\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Vb\";" ascii
    $s18 = "return \"MIl\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"ADy\";})(" ascii
    $s19 = "ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Vf\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}