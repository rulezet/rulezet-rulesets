rule TTP_XOR_QUAD_CurrentVersionRun_ade6 {
  strings:
    $key_ade6 = { fe 89 [2] da 87 [2] f1 ab [2] df 89 [2] cb 92 [2] c4 88 [2] da 95 [2] d8 94 [2] c3 92 [2] df 95 [2] c3 ba }

  condition:
    any of them
}