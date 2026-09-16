rule TTP_XOR_QUAD_CurrentVersionRun_ad1f {
  strings:
    $key_ad1f = { fe 70 [2] da 7e [2] f1 52 [2] df 70 [2] cb 6b [2] c4 71 [2] da 6c [2] d8 6d [2] c3 6b [2] df 6c [2] c3 43 }

  condition:
    any of them
}