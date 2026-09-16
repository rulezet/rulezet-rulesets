rule _20160921_78345276f684d53628bbcac810994182_20160921_7dec24f022af_5414 {
  meta:
    description = "datamaliciousorder - from files 20160921_78345276f684d53628bbcac810994182.js, 20160921_7dec24f022af3c1ffe46748172dd6cad.js, 20160921_b714100d69b955de920a302ff8bef7db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17b203684b4f2284de883c81e8fef63ea03c36bd0599ccb85d3175be35d9ac6d"
    hash2       = "402e919998fdba69cb3992879db4f947916245c38915db643643952fa450e947"
    hash3       = "fc43d54db3c24d6f7ce2d47a45ffcd0768d5cfe90e405322e477be98fe4a8170"

  strings:
    $s1 = "\"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(funct" ascii
    $s2 = "turn \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})()" ascii
    $s3 = "ction fuck(){return \"Jo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return" ascii
    $s4 = "n \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(fu" ascii
    $s5 = "on fuck(){return \"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}