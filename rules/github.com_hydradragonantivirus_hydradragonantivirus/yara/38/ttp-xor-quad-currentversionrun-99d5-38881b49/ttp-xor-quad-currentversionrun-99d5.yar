rule TTP_XOR_QUAD_CurrentVersionRun_99d5 {
  strings:
    $key_99d5 = { ca ba [2] ee b4 [2] c5 98 [2] eb ba [2] ff a1 [2] f0 bb [2] ee a6 [2] ec a7 [2] f7 a1 [2] eb a6 [2] f7 89 }

  condition:
    any of them
}