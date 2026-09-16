rule TTP_XOR_QUAD_CurrentVersionRun_ad6e {
  strings:
    $key_ad6e = { fe 01 [2] da 0f [2] f1 23 [2] df 01 [2] cb 1a [2] c4 00 [2] da 1d [2] d8 1c [2] c3 1a [2] df 1d [2] c3 32 }

  condition:
    any of them
}