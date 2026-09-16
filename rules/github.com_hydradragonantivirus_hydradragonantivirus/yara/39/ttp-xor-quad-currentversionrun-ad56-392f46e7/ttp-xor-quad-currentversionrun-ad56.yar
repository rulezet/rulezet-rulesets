rule TTP_XOR_QUAD_CurrentVersionRun_ad56 {
  strings:
    $key_ad56 = { fe 39 [2] da 37 [2] f1 1b [2] df 39 [2] cb 22 [2] c4 38 [2] da 25 [2] d8 24 [2] c3 22 [2] df 25 [2] c3 0a }

  condition:
    any of them
}