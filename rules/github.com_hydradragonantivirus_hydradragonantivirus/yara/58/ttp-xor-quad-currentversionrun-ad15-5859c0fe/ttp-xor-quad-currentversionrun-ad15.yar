rule TTP_XOR_QUAD_CurrentVersionRun_ad15 {
  strings:
    $key_ad15 = { fe 7a [2] da 74 [2] f1 58 [2] df 7a [2] cb 61 [2] c4 7b [2] da 66 [2] d8 67 [2] c3 61 [2] df 66 [2] c3 49 }

  condition:
    any of them
}