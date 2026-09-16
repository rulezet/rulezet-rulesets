rule TTP_XOR_QUAD_CurrentVersionRun_ad72 {
  strings:
    $key_ad72 = { fe 1d [2] da 13 [2] f1 3f [2] df 1d [2] cb 06 [2] c4 1c [2] da 01 [2] d8 00 [2] c3 06 [2] df 01 [2] c3 2e }

  condition:
    any of them
}