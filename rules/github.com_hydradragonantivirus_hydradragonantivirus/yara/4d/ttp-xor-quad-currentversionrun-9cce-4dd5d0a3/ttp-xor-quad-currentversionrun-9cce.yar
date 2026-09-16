rule TTP_XOR_QUAD_CurrentVersionRun_9cce {
  strings:
    $key_9cce = { cf a1 [2] eb af [2] c0 83 [2] ee a1 [2] fa ba [2] f5 a0 [2] eb bd [2] e9 bc [2] f2 ba [2] ee bd [2] f2 92 }

  condition:
    any of them
}