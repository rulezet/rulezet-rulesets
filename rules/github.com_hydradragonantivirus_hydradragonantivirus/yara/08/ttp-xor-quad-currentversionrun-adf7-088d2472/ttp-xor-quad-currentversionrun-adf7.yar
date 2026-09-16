rule TTP_XOR_QUAD_CurrentVersionRun_adf7 {
  strings:
    $key_adf7 = { fe 98 [2] da 96 [2] f1 ba [2] df 98 [2] cb 83 [2] c4 99 [2] da 84 [2] d8 85 [2] c3 83 [2] df 84 [2] c3 ab }

  condition:
    any of them
}