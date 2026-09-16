rule TTP_XOR_QUAD_CurrentVersionRun_ad77 {
  strings:
    $key_ad77 = { fe 18 [2] da 16 [2] f1 3a [2] df 18 [2] cb 03 [2] c4 19 [2] da 04 [2] d8 05 [2] c3 03 [2] df 04 [2] c3 2b }

  condition:
    any of them
}