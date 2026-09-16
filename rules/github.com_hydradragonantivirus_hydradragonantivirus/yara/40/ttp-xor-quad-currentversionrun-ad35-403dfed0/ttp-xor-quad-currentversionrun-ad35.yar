rule TTP_XOR_QUAD_CurrentVersionRun_ad35 {
  strings:
    $key_ad35 = { fe 5a [2] da 54 [2] f1 78 [2] df 5a [2] cb 41 [2] c4 5b [2] da 46 [2] d8 47 [2] c3 41 [2] df 46 [2] c3 69 }

  condition:
    any of them
}