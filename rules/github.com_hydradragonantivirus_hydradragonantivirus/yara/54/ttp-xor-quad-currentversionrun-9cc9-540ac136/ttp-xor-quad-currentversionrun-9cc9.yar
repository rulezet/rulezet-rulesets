rule TTP_XOR_QUAD_CurrentVersionRun_9cc9 {
  strings:
    $key_9cc9 = { cf a6 [2] eb a8 [2] c0 84 [2] ee a6 [2] fa bd [2] f5 a7 [2] eb ba [2] e9 bb [2] f2 bd [2] ee ba [2] f2 95 }

  condition:
    any of them
}