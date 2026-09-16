rule TTP_XOR_QUAD_CurrentVersionRun_ad06 {
  strings:
    $key_ad06 = { fe 69 [2] da 67 [2] f1 4b [2] df 69 [2] cb 72 [2] c4 68 [2] da 75 [2] d8 74 [2] c3 72 [2] df 75 [2] c3 5a }

  condition:
    any of them
}