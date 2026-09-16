rule _20160921_2e85dfa9a5ea92be677fa9eceee4f8b1_20160921_ecd98b74e6a5_50 {
  meta:
    description = "datamaliciousorder - from files 20160921_2e85dfa9a5ea92be677fa9eceee4f8b1.js, 20160921_ecd98b74e6a52b1227b09228f92cb495.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd958e388f97aa8b73e103ada622a36250446b5740c2e70d0bf844240c0968c2"
    hash2       = "8930637b40db8c97df91bff2cf5b4021d0bcb2f6a204f27249176fe3d6d4120e"

  strings:
    $s1  = "nction fuck(){return \"Zy\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s2  = "ion fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return " ascii
    $s3  = "function fuck(){return \"UXf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){re" ascii
    $s4  = "urn \"PDf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(" ascii
    $s5  = ",(function fuck(){return \"Np\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){r" ascii
    $s6  = "tion fuck(){return \"Dc\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return " ascii
    $s7  = "(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"UXf\";})(),(function fuck(" ascii
    $s8  = "(){return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"GNm\"" ascii
    $s9  = "eturn \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Ve\";})(),(" ascii
    $s10 = "rn \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"PDf\";})(),(f" ascii
    $s11 = ";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xw\";})(),(function fuck" ascii
    $s12 = "(function fuck(){return \"DRx\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){r" ascii
    $s13 = "Df\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"RAi\";})(),(functi" ascii
    $s14 = "nction fuck(){return \"Hs\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){retur" ascii
    $s15 = "\"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"We\";})(),(funct" ascii
    $s16 = "Ai\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"USf\";})(),(functio" ascii
    $s17 = "u\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(functio" ascii
    $s18 = ";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Jo\";})(),(function fuc" ascii
    $s19 = " fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"C" ascii
    $s20 = "tion fuck(){return \"XFd\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}