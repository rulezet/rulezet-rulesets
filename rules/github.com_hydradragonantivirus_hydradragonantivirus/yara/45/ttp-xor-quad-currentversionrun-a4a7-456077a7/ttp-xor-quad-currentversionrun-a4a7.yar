rule TTP_XOR_QUAD_CurrentVersionRun_a4a7 {
  strings:
    $key_a4a7 = { f7 c8 [2] d3 c6 [2] f8 ea [2] d6 c8 [2] c2 d3 [2] cd c9 [2] d3 d4 [2] d1 d5 [2] ca d3 [2] d6 d4 [2] ca fb }

  condition:
    any of them
}