rule TTP_XOR_QUAD_CurrentVersionRun_ad65 {
  strings:
    $key_ad65 = { fe 0a [2] da 04 [2] f1 28 [2] df 0a [2] cb 11 [2] c4 0b [2] da 16 [2] d8 17 [2] c3 11 [2] df 16 [2] c3 39 }

  condition:
    any of them
}