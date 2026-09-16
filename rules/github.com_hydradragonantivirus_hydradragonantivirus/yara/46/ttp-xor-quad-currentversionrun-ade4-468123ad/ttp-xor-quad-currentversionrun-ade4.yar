rule TTP_XOR_QUAD_CurrentVersionRun_ade4 {
  strings:
    $key_ade4 = { fe 8b [2] da 85 [2] f1 a9 [2] df 8b [2] cb 90 [2] c4 8a [2] da 97 [2] d8 96 [2] c3 90 [2] df 97 [2] c3 b8 }

  condition:
    any of them
}