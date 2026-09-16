rule TTP_XOR_QUAD_CurrentVersionRun_99c9 {
  strings:
    $key_99c9 = { ca a6 [2] ee a8 [2] c5 84 [2] eb a6 [2] ff bd [2] f0 a7 [2] ee ba [2] ec bb [2] f7 bd [2] eb ba [2] f7 95 }

  condition:
    any of them
}