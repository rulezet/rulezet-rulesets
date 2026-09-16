rule TTP_XOR_QUAD_CurrentVersionRun_ad5d {
  strings:
    $key_ad5d = { fe 32 [2] da 3c [2] f1 10 [2] df 32 [2] cb 29 [2] c4 33 [2] da 2e [2] d8 2f [2] c3 29 [2] df 2e [2] c3 01 }

  condition:
    any of them
}