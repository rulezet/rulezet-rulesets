rule _20160921_3214ea252f2a25e018a03ee43ce952f5_20160921_37c1eae8c734_1692 {
  meta:
    description = "datamaliciousorder - from files 20160921_3214ea252f2a25e018a03ee43ce952f5.js, 20160921_37c1eae8c73482d7ccd62bb1c25f74b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e406c80b4ad80ad1898c09cec0694086bfb24caedb8bc3bb213513d0b4232bd3"
    hash2       = "8e724c0f7c8722eec82dd0f37b13b38ab5c357aeccb2cc6c36efae80bae66a8a"

  strings:
    $s1  = "n fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"" ascii
    $s2  = "ck(){return \"LGo\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"GJx" ascii
    $s3  = "\"Wo0\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(func" ascii
    $s4  = "rn \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})()];" fullword ascii
    $s5  = "function fuck(){return \"ZVi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){re" ascii
    $s6  = "turn \"Za\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(" ascii
    $s7  = "(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"ADy\";}" ascii
    $s8  = "k(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"EHo\"" ascii
    $s9  = " fuck(){return \"UXf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"" ascii
    $s10 = "n \"Zy\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"Vb\";})(),(funct" ascii
    $s11 = "Ug\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Hs\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}