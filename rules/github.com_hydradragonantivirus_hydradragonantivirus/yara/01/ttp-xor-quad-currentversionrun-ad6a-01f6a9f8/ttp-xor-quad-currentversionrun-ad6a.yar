rule TTP_XOR_QUAD_CurrentVersionRun_ad6a {
  strings:
    $key_ad6a = { fe 05 [2] da 0b [2] f1 27 [2] df 05 [2] cb 1e [2] c4 04 [2] da 19 [2] d8 18 [2] c3 1e [2] df 19 [2] c3 36 }

  condition:
    any of them
}