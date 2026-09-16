rule TTP_XOR_QUAD_CurrentVersionRun_ad47 {
  strings:
    $key_ad47 = { fe 28 [2] da 26 [2] f1 0a [2] df 28 [2] cb 33 [2] c4 29 [2] da 34 [2] d8 35 [2] c3 33 [2] df 34 [2] c3 1b }

  condition:
    any of them
}