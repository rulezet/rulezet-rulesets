rule _20160921_20daf816cda5af37e984359023f15db2_20160921_ad0fbcfca87e_4666 {
  meta:
    description = "datamaliciousorder - from files 20160921_20daf816cda5af37e984359023f15db2.js, 20160921_ad0fbcfca87e48302530672c4ceab093.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a45ccf6470d4ee194ed220125c42c5ac5d7c4b8a46cce738c6d12e9cc0bafea8"
    hash2       = "481451a3850055fd2d398d5707171f67d2aa3cd019214d6b67f539efc81ca7bb"

  strings:
    $s1 = "ck(){return \"DRx\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"IPu" ascii
    $s2 = "on fuck(){return \"Vb\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"" ascii
    $s3 = "n \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(fu" ascii
    $s4 = "urn \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(fu" ascii
    $s5 = "eturn \"MUs\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"UXf\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}