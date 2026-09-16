rule TTP_XOR_QUAD_CurrentVersionRun_9cd3 {
  strings:
    $key_9cd3 = { cf bc [2] eb b2 [2] c0 9e [2] ee bc [2] fa a7 [2] f5 bd [2] eb a0 [2] e9 a1 [2] f2 a7 [2] ee a0 [2] f2 8f }

  condition:
    any of them
}