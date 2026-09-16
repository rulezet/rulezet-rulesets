rule TTP_XOR_QUAD_CurrentVersionRun_adfa {
  strings:
    $key_adfa = { fe 95 [2] da 9b [2] f1 b7 [2] df 95 [2] cb 8e [2] c4 94 [2] da 89 [2] d8 88 [2] c3 8e [2] df 89 [2] c3 a6 }

  condition:
    any of them
}