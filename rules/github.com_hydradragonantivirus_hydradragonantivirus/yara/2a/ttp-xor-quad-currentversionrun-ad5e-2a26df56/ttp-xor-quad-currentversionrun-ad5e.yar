rule TTP_XOR_QUAD_CurrentVersionRun_ad5e {
  strings:
    $key_ad5e = { fe 31 [2] da 3f [2] f1 13 [2] df 31 [2] cb 2a [2] c4 30 [2] da 2d [2] d8 2c [2] c3 2a [2] df 2d [2] c3 02 }

  condition:
    any of them
}