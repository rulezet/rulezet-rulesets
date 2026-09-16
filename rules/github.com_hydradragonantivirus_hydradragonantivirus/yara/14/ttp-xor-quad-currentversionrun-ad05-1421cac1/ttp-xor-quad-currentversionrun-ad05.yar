rule TTP_XOR_QUAD_CurrentVersionRun_ad05 {
  strings:
    $key_ad05 = { fe 6a [2] da 64 [2] f1 48 [2] df 6a [2] cb 71 [2] c4 6b [2] da 76 [2] d8 77 [2] c3 71 [2] df 76 [2] c3 59 }

  condition:
    any of them
}