rule TTP_XOR_QUAD_CurrentVersionRun_ad3f {
  strings:
    $key_ad3f = { fe 50 [2] da 5e [2] f1 72 [2] df 50 [2] cb 4b [2] c4 51 [2] da 4c [2] d8 4d [2] c3 4b [2] df 4c [2] c3 63 }

  condition:
    any of them
}