rule TTP_XOR_QUAD_CurrentVersionRun_ad45 {
  strings:
    $key_ad45 = { fe 2a [2] da 24 [2] f1 08 [2] df 2a [2] cb 31 [2] c4 2b [2] da 36 [2] d8 37 [2] c3 31 [2] df 36 [2] c3 19 }

  condition:
    any of them
}