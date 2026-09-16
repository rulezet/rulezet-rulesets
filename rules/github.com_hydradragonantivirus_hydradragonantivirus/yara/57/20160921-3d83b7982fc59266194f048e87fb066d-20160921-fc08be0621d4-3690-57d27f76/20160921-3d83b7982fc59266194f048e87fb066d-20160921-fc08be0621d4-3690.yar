rule _20160921_3d83b7982fc59266194f048e87fb066d_20160921_fc08be0621d4_3690 {
  meta:
    description = "datamaliciousorder - from files 20160921_3d83b7982fc59266194f048e87fb066d.js, 20160921_fc08be0621d4ffbced0eaca2b2622b07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f14778492463eaa86aec448221dcd9e88defb1f42404b2b80d42b0d0c41ffa66"
    hash2       = "1641412d2cba74b5cd1b4c4619c995601c42039d472339eb7cb10d97e1d47339"

  strings:
    $s1 = "on fuck(){return \"GWo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s2 = "eturn \"NKq\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})()" ascii
    $s3 = "v\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s4 = "IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(functio" ascii
    $s5 = ";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"MUs\";})(),(function fu" ascii
    $s6 = "eturn \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Qh\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}