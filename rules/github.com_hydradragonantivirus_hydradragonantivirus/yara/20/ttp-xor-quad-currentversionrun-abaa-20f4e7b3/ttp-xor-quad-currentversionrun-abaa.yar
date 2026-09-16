rule TTP_XOR_QUAD_CurrentVersionRun_abaa {
  strings:
    $key_abaa = { f8 c5 [2] dc cb [2] f7 e7 [2] d9 c5 [2] cd de [2] c2 c4 [2] dc d9 [2] de d8 [2] c5 de [2] d9 d9 [2] c5 f6 }

  condition:
    any of them
}