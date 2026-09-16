rule TTP_XOR_QUAD_CurrentVersionRun_ad66 {
  strings:
    $key_ad66 = { fe 09 [2] da 07 [2] f1 2b [2] df 09 [2] cb 12 [2] c4 08 [2] da 15 [2] d8 14 [2] c3 12 [2] df 15 [2] c3 3a }

  condition:
    any of them
}