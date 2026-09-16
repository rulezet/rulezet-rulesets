rule TTP_XOR_QUAD_CurrentVersionRun_bfaa {
  strings:
    $key_bfaa = { ec c5 [2] c8 cb [2] e3 e7 [2] cd c5 [2] d9 de [2] d6 c4 [2] c8 d9 [2] ca d8 [2] d1 de [2] cd d9 [2] d1 f6 }

  condition:
    any of them
}