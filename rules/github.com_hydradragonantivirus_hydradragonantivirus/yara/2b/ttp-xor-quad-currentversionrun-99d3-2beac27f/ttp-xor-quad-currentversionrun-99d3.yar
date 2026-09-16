rule TTP_XOR_QUAD_CurrentVersionRun_99d3 {
  strings:
    $key_99d3 = { ca bc [2] ee b2 [2] c5 9e [2] eb bc [2] ff a7 [2] f0 bd [2] ee a0 [2] ec a1 [2] f7 a7 [2] eb a0 [2] f7 8f }

  condition:
    any of them
}