rule TTP_XOR_QUAD_CurrentVersionRun_ad78 {
  strings:
    $key_ad78 = { fe 17 [2] da 19 [2] f1 35 [2] df 17 [2] cb 0c [2] c4 16 [2] da 0b [2] d8 0a [2] c3 0c [2] df 0b [2] c3 24 }

  condition:
    any of them
}