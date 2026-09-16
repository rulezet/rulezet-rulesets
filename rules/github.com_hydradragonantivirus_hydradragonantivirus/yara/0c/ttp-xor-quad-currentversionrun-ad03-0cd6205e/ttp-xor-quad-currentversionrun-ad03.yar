rule TTP_XOR_QUAD_CurrentVersionRun_ad03 {
  strings:
    $key_ad03 = { fe 6c [2] da 62 [2] f1 4e [2] df 6c [2] cb 77 [2] c4 6d [2] da 70 [2] d8 71 [2] c3 77 [2] df 70 [2] c3 5f }

  condition:
    any of them
}