rule TTP_XOR_QUAD_CurrentVersionRun_ad70 {
  strings:
    $key_ad70 = { fe 1f [2] da 11 [2] f1 3d [2] df 1f [2] cb 04 [2] c4 1e [2] da 03 [2] d8 02 [2] c3 04 [2] df 03 [2] c3 2c }

  condition:
    any of them
}