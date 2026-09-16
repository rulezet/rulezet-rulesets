rule TTP_XOR_QUAD_CurrentVersionRun_adef {
  strings:
    $key_adef = { fe 80 [2] da 8e [2] f1 a2 [2] df 80 [2] cb 9b [2] c4 81 [2] da 9c [2] d8 9d [2] c3 9b [2] df 9c [2] c3 b3 }

  condition:
    any of them
}