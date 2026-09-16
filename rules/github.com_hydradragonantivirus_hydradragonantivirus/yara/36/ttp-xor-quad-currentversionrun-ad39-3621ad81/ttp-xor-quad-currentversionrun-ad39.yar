rule TTP_XOR_QUAD_CurrentVersionRun_ad39 {
  strings:
    $key_ad39 = { fe 56 [2] da 58 [2] f1 74 [2] df 56 [2] cb 4d [2] c4 57 [2] da 4a [2] d8 4b [2] c3 4d [2] df 4a [2] c3 65 }

  condition:
    any of them
}