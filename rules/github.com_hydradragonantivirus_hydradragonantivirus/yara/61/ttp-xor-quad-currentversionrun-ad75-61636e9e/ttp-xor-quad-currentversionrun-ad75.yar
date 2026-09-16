rule TTP_XOR_QUAD_CurrentVersionRun_ad75 {
  strings:
    $key_ad75 = { fe 1a [2] da 14 [2] f1 38 [2] df 1a [2] cb 01 [2] c4 1b [2] da 06 [2] d8 07 [2] c3 01 [2] df 06 [2] c3 29 }

  condition:
    any of them
}