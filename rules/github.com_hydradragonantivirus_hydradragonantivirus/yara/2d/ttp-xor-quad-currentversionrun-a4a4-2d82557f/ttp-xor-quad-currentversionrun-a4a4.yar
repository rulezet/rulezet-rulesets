rule TTP_XOR_QUAD_CurrentVersionRun_a4a4 {
  strings:
    $key_a4a4 = { f7 cb [2] d3 c5 [2] f8 e9 [2] d6 cb [2] c2 d0 [2] cd ca [2] d3 d7 [2] d1 d6 [2] ca d0 [2] d6 d7 [2] ca f8 }

  condition:
    any of them
}