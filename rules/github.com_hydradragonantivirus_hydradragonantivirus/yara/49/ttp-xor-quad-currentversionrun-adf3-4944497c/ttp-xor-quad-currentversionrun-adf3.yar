rule TTP_XOR_QUAD_CurrentVersionRun_adf3 {
  strings:
    $key_adf3 = { fe 9c [2] da 92 [2] f1 be [2] df 9c [2] cb 87 [2] c4 9d [2] da 80 [2] d8 81 [2] c3 87 [2] df 80 [2] c3 af }

  condition:
    any of them
}