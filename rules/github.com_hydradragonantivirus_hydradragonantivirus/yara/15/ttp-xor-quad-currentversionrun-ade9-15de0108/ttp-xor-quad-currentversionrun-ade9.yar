rule TTP_XOR_QUAD_CurrentVersionRun_ade9 {
  strings:
    $key_ade9 = { fe 86 [2] da 88 [2] f1 a4 [2] df 86 [2] cb 9d [2] c4 87 [2] da 9a [2] d8 9b [2] c3 9d [2] df 9a [2] c3 b5 }

  condition:
    any of them
}