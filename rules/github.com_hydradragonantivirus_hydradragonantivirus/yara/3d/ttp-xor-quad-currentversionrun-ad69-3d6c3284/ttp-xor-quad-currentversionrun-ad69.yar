rule TTP_XOR_QUAD_CurrentVersionRun_ad69 {
  strings:
    $key_ad69 = { fe 06 [2] da 08 [2] f1 24 [2] df 06 [2] cb 1d [2] c4 07 [2] da 1a [2] d8 1b [2] c3 1d [2] df 1a [2] c3 35 }

  condition:
    any of them
}