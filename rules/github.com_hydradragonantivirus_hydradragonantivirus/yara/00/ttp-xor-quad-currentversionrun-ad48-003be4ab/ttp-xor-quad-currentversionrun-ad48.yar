rule TTP_XOR_QUAD_CurrentVersionRun_ad48 {
  strings:
    $key_ad48 = { fe 27 [2] da 29 [2] f1 05 [2] df 27 [2] cb 3c [2] c4 26 [2] da 3b [2] d8 3a [2] c3 3c [2] df 3b [2] c3 14 }

  condition:
    any of them
}