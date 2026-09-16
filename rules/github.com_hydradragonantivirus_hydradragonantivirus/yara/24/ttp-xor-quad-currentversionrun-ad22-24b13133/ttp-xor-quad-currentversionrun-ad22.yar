rule TTP_XOR_QUAD_CurrentVersionRun_ad22 {
  strings:
    $key_ad22 = { fe 4d [2] da 43 [2] f1 6f [2] df 4d [2] cb 56 [2] c4 4c [2] da 51 [2] d8 50 [2] c3 56 [2] df 51 [2] c3 7e }

  condition:
    any of them
}