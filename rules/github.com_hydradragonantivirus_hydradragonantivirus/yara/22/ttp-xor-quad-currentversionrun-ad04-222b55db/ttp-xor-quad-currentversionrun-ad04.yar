rule TTP_XOR_QUAD_CurrentVersionRun_ad04 {
  strings:
    $key_ad04 = { fe 6b [2] da 65 [2] f1 49 [2] df 6b [2] cb 70 [2] c4 6a [2] da 77 [2] d8 76 [2] c3 70 [2] df 77 [2] c3 58 }

  condition:
    any of them
}