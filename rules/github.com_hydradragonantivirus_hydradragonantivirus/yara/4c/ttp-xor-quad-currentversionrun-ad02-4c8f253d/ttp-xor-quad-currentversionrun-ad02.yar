rule TTP_XOR_QUAD_CurrentVersionRun_ad02 {
  strings:
    $key_ad02 = { fe 6d [2] da 63 [2] f1 4f [2] df 6d [2] cb 76 [2] c4 6c [2] da 71 [2] d8 70 [2] c3 76 [2] df 71 [2] c3 5e }

  condition:
    any of them
}