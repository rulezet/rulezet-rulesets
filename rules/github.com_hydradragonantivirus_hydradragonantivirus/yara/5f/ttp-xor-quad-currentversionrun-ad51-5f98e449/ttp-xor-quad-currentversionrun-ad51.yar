rule TTP_XOR_QUAD_CurrentVersionRun_ad51 {
  strings:
    $key_ad51 = { fe 3e [2] da 30 [2] f1 1c [2] df 3e [2] cb 25 [2] c4 3f [2] da 22 [2] d8 23 [2] c3 25 [2] df 22 [2] c3 0d }

  condition:
    any of them
}