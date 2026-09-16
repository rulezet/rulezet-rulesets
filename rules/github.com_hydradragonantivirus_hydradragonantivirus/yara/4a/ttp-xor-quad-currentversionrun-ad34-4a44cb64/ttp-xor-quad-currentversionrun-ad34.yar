rule TTP_XOR_QUAD_CurrentVersionRun_ad34 {
  strings:
    $key_ad34 = { fe 5b [2] da 55 [2] f1 79 [2] df 5b [2] cb 40 [2] c4 5a [2] da 47 [2] d8 46 [2] c3 40 [2] df 47 [2] c3 68 }

  condition:
    any of them
}