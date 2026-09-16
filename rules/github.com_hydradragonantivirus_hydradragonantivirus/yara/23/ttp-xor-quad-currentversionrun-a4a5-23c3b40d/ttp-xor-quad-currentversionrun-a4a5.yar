rule TTP_XOR_QUAD_CurrentVersionRun_a4a5 {
  strings:
    $key_a4a5 = { f7 ca [2] d3 c4 [2] f8 e8 [2] d6 ca [2] c2 d1 [2] cd cb [2] d3 d6 [2] d1 d7 [2] ca d1 [2] d6 d6 [2] ca f9 }

  condition:
    any of them
}