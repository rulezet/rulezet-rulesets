rule TTP_XOR_QUAD_CurrentVersionRun_adf4 {
  strings:
    $key_adf4 = { fe 9b [2] da 95 [2] f1 b9 [2] df 9b [2] cb 80 [2] c4 9a [2] da 87 [2] d8 86 [2] c3 80 [2] df 87 [2] c3 a8 }

  condition:
    any of them
}