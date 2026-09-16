rule TTP_XOR_QUAD_CurrentVersionRun_b8aa {
  strings:
    $key_b8aa = { eb c5 [2] cf cb [2] e4 e7 [2] ca c5 [2] de de [2] d1 c4 [2] cf d9 [2] cd d8 [2] d6 de [2] ca d9 [2] d6 f6 }

  condition:
    any of them
}