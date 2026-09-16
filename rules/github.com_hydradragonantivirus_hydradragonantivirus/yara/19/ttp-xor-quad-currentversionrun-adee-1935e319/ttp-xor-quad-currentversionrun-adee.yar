rule TTP_XOR_QUAD_CurrentVersionRun_adee {
  strings:
    $key_adee = { fe 81 [2] da 8f [2] f1 a3 [2] df 81 [2] cb 9a [2] c4 80 [2] da 9d [2] d8 9c [2] c3 9a [2] df 9d [2] c3 b2 }

  condition:
    any of them
}