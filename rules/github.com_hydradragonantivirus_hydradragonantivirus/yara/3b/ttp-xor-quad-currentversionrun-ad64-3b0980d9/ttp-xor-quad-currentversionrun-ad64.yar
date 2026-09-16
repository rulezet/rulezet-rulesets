rule TTP_XOR_QUAD_CurrentVersionRun_ad64 {
  strings:
    $key_ad64 = { fe 0b [2] da 05 [2] f1 29 [2] df 0b [2] cb 10 [2] c4 0a [2] da 17 [2] d8 16 [2] c3 10 [2] df 17 [2] c3 38 }

  condition:
    any of them
}