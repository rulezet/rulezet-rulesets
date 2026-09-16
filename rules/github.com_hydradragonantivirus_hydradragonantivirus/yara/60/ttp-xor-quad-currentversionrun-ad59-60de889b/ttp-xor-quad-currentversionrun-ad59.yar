rule TTP_XOR_QUAD_CurrentVersionRun_ad59 {
  strings:
    $key_ad59 = { fe 36 [2] da 38 [2] f1 14 [2] df 36 [2] cb 2d [2] c4 37 [2] da 2a [2] d8 2b [2] c3 2d [2] df 2a [2] c3 05 }

  condition:
    any of them
}