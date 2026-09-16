rule TTP_XOR_QUAD_CurrentVersionRun_ad09 {
  strings:
    $key_ad09 = { fe 66 [2] da 68 [2] f1 44 [2] df 66 [2] cb 7d [2] c4 67 [2] da 7a [2] d8 7b [2] c3 7d [2] df 7a [2] c3 55 }

  condition:
    any of them
}