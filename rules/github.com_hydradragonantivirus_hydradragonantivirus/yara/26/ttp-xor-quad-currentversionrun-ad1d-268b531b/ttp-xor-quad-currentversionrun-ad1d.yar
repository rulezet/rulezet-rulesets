rule TTP_XOR_QUAD_CurrentVersionRun_ad1d {
  strings:
    $key_ad1d = { fe 72 [2] da 7c [2] f1 50 [2] df 72 [2] cb 69 [2] c4 73 [2] da 6e [2] d8 6f [2] c3 69 [2] df 6e [2] c3 41 }

  condition:
    any of them
}