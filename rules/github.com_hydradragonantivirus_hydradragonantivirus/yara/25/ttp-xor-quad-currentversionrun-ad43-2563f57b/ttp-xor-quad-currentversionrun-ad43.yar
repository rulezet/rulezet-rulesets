rule TTP_XOR_QUAD_CurrentVersionRun_ad43 {
  strings:
    $key_ad43 = { fe 2c [2] da 22 [2] f1 0e [2] df 2c [2] cb 37 [2] c4 2d [2] da 30 [2] d8 31 [2] c3 37 [2] df 30 [2] c3 1f }

  condition:
    any of them
}