rule TTP_XOR_QUAD_CurrentVersionRun_a4aa {
  strings:
    $key_a4aa = { f7 c5 [2] d3 cb [2] f8 e7 [2] d6 c5 [2] c2 de [2] cd c4 [2] d3 d9 [2] d1 d8 [2] ca de [2] d6 d9 [2] ca f6 }

  condition:
    any of them
}