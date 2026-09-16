rule TTP_XOR_QUAD_CurrentVersionRun_ad36 {
  strings:
    $key_ad36 = { fe 59 [2] da 57 [2] f1 7b [2] df 59 [2] cb 42 [2] c4 58 [2] da 45 [2] d8 44 [2] c3 42 [2] df 45 [2] c3 6a }

  condition:
    any of them
}