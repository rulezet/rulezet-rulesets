rule TTP_XOR_QUAD_CurrentVersionRun_9ccf {
  strings:
    $key_9ccf = { cf a0 [2] eb ae [2] c0 82 [2] ee a0 [2] fa bb [2] f5 a1 [2] eb bc [2] e9 bd [2] f2 bb [2] ee bc [2] f2 93 }

  condition:
    any of them
}