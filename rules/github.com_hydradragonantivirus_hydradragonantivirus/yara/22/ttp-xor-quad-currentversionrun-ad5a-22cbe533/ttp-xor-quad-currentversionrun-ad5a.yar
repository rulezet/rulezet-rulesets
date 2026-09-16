rule TTP_XOR_QUAD_CurrentVersionRun_ad5a {
  strings:
    $key_ad5a = { fe 35 [2] da 3b [2] f1 17 [2] df 35 [2] cb 2e [2] c4 34 [2] da 29 [2] d8 28 [2] c3 2e [2] df 29 [2] c3 06 }

  condition:
    any of them
}