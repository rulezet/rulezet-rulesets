rule TTP_XOR_QUAD_CurrentVersionRun_ad7c {
  strings:
    $key_ad7c = { fe 13 [2] da 1d [2] f1 31 [2] df 13 [2] cb 08 [2] c4 12 [2] da 0f [2] d8 0e [2] c3 08 [2] df 0f [2] c3 20 }

  condition:
    any of them
}