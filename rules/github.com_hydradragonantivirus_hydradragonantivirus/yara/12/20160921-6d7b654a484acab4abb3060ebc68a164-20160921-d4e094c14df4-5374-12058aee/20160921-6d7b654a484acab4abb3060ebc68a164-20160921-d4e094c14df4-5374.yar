rule _20160921_6d7b654a484acab4abb3060ebc68a164_20160921_d4e094c14df4_5374 {
  meta:
    description = "datamaliciousorder - from files 20160921_6d7b654a484acab4abb3060ebc68a164.js, 20160921_d4e094c14df45f61de0e1163f51e03e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2840e0696eacd7118885eaede05c3ef29d9cc682ba227d7797a60be4872d86c9"
    hash2       = "2877b2ace685858babd88dd0ef1659f49f21c3f8b907e5b3889ec46bf3a7104a"

  strings:
    $s1 = "n \"AUx\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Tv\";})(),(fu" ascii
    $s2 = "fuck(){return \"Py\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"AJ" ascii
    $s3 = "rn \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Cd\";})(),(f" ascii
    $s4 = "eturn \"Za\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Py\";})()," ascii
    $s5 = "n fuck(){return \"CTm\";})(),(function fuck(){return \"ILp\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}