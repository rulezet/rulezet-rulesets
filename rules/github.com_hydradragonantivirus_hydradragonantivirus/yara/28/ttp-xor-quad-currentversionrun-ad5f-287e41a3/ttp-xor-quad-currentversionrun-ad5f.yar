rule TTP_XOR_QUAD_CurrentVersionRun_ad5f {
  strings:
    $key_ad5f = { fe 30 [2] da 3e [2] f1 12 [2] df 30 [2] cb 2b [2] c4 31 [2] da 2c [2] d8 2d [2] c3 2b [2] df 2c [2] c3 03 }

  condition:
    any of them
}