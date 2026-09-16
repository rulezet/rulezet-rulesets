rule TTP_XOR_QUAD_CurrentVersionRun_adea {
  strings:
    $key_adea = { fe 85 [2] da 8b [2] f1 a7 [2] df 85 [2] cb 9e [2] c4 84 [2] da 99 [2] d8 98 [2] c3 9e [2] df 99 [2] c3 b6 }

  condition:
    any of them
}