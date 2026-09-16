rule TTP_XOR_QUAD_CurrentVersionRun_ad3a {
  strings:
    $key_ad3a = { fe 55 [2] da 5b [2] f1 77 [2] df 55 [2] cb 4e [2] c4 54 [2] da 49 [2] d8 48 [2] c3 4e [2] df 49 [2] c3 66 }

  condition:
    any of them
}