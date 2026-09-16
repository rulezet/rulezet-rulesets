rule TTP_XOR_QUAD_CurrentVersionRun_ad49 {
  strings:
    $key_ad49 = { fe 26 [2] da 28 [2] f1 04 [2] df 26 [2] cb 3d [2] c4 27 [2] da 3a [2] d8 3b [2] c3 3d [2] df 3a [2] c3 15 }

  condition:
    any of them
}