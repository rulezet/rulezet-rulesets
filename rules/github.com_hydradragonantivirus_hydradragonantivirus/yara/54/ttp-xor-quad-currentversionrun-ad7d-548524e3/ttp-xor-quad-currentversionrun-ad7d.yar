rule TTP_XOR_QUAD_CurrentVersionRun_ad7d {
  strings:
    $key_ad7d = { fe 12 [2] da 1c [2] f1 30 [2] df 12 [2] cb 09 [2] c4 13 [2] da 0e [2] d8 0f [2] c3 09 [2] df 0e [2] c3 21 }

  condition:
    any of them
}