rule TTP_XOR_QUAD_CurrentVersionRun_ad57 {
  strings:
    $key_ad57 = { fe 38 [2] da 36 [2] f1 1a [2] df 38 [2] cb 23 [2] c4 39 [2] da 24 [2] d8 25 [2] c3 23 [2] df 24 [2] c3 0b }

  condition:
    any of them
}