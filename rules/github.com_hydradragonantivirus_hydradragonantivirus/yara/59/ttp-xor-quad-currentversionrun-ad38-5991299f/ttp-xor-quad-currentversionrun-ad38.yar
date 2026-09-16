rule TTP_XOR_QUAD_CurrentVersionRun_ad38 {
  strings:
    $key_ad38 = { fe 57 [2] da 59 [2] f1 75 [2] df 57 [2] cb 4c [2] c4 56 [2] da 4b [2] d8 4a [2] c3 4c [2] df 4b [2] c3 64 }

  condition:
    any of them
}