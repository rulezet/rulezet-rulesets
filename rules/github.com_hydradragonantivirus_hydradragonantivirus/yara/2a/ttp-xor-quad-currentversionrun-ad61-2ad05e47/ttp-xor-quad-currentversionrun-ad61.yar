rule TTP_XOR_QUAD_CurrentVersionRun_ad61 {
  strings:
    $key_ad61 = { fe 0e [2] da 00 [2] f1 2c [2] df 0e [2] cb 15 [2] c4 0f [2] da 12 [2] d8 13 [2] c3 15 [2] df 12 [2] c3 3d }

  condition:
    any of them
}