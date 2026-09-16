rule TTP_XOR_QUAD_CurrentVersionRun_ad6d {
  strings:
    $key_ad6d = { fe 02 [2] da 0c [2] f1 20 [2] df 02 [2] cb 19 [2] c4 03 [2] da 1e [2] d8 1f [2] c3 19 [2] df 1e [2] c3 31 }

  condition:
    any of them
}