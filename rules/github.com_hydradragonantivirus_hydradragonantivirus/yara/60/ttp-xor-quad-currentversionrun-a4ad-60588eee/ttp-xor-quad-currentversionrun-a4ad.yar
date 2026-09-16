rule TTP_XOR_QUAD_CurrentVersionRun_a4ad {
  strings:
    $key_a4ad = { f7 c2 [2] d3 cc [2] f8 e0 [2] d6 c2 [2] c2 d9 [2] cd c3 [2] d3 de [2] d1 df [2] ca d9 [2] d6 de [2] ca f1 }

  condition:
    any of them
}