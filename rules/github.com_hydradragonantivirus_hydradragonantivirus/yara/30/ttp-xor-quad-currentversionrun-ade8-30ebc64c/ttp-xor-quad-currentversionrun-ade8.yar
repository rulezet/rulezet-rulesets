rule TTP_XOR_QUAD_CurrentVersionRun_ade8 {
  strings:
    $key_ade8 = { fe 87 [2] da 89 [2] f1 a5 [2] df 87 [2] cb 9c [2] c4 86 [2] da 9b [2] d8 9a [2] c3 9c [2] df 9b [2] c3 b4 }

  condition:
    any of them
}