rule TTP_XOR_QUAD_CurrentVersionRun_ad73 {
  strings:
    $key_ad73 = { fe 1c [2] da 12 [2] f1 3e [2] df 1c [2] cb 07 [2] c4 1d [2] da 00 [2] d8 01 [2] c3 07 [2] df 00 [2] c3 2f }

  condition:
    any of them
}