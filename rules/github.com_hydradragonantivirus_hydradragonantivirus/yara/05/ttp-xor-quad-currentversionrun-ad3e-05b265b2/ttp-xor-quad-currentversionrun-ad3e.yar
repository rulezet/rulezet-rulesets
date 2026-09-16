rule TTP_XOR_QUAD_CurrentVersionRun_ad3e {
  strings:
    $key_ad3e = { fe 51 [2] da 5f [2] f1 73 [2] df 51 [2] cb 4a [2] c4 50 [2] da 4d [2] d8 4c [2] c3 4a [2] df 4d [2] c3 62 }

  condition:
    any of them
}