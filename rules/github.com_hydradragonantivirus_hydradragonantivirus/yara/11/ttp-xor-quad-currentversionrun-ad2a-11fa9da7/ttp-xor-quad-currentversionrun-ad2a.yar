rule TTP_XOR_QUAD_CurrentVersionRun_ad2a {
  strings:
    $key_ad2a = { fe 45 [2] da 4b [2] f1 67 [2] df 45 [2] cb 5e [2] c4 44 [2] da 59 [2] d8 58 [2] c3 5e [2] df 59 [2] c3 76 }

  condition:
    any of them
}