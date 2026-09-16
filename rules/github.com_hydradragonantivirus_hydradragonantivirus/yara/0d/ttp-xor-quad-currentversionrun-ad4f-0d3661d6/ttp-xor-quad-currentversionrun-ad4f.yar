rule TTP_XOR_QUAD_CurrentVersionRun_ad4f {
  strings:
    $key_ad4f = { fe 20 [2] da 2e [2] f1 02 [2] df 20 [2] cb 3b [2] c4 21 [2] da 3c [2] d8 3d [2] c3 3b [2] df 3c [2] c3 13 }

  condition:
    any of them
}