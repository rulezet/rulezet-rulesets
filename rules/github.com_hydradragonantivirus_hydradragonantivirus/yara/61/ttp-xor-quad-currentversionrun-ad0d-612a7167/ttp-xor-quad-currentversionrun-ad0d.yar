rule TTP_XOR_QUAD_CurrentVersionRun_ad0d {
  strings:
    $key_ad0d = { fe 62 [2] da 6c [2] f1 40 [2] df 62 [2] cb 79 [2] c4 63 [2] da 7e [2] d8 7f [2] c3 79 [2] df 7e [2] c3 51 }

  condition:
    any of them
}