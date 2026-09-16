rule TTP_XOR_QUAD_CurrentVersionRun_adfe {
  strings:
    $key_adfe = { fe 91 [2] da 9f [2] f1 b3 [2] df 91 [2] cb 8a [2] c4 90 [2] da 8d [2] d8 8c [2] c3 8a [2] df 8d [2] c3 a2 }

  condition:
    any of them
}