rule TTP_XOR_QUAD_CurrentVersionRun_ad21 {
  strings:
    $key_ad21 = { fe 4e [2] da 40 [2] f1 6c [2] df 4e [2] cb 55 [2] c4 4f [2] da 52 [2] d8 53 [2] c3 55 [2] df 52 [2] c3 7d }

  condition:
    any of them
}