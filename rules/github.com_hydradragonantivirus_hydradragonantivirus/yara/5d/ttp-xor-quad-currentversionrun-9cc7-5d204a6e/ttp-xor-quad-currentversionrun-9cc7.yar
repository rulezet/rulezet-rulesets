rule TTP_XOR_QUAD_CurrentVersionRun_9cc7 {
  strings:
    $key_9cc7 = { cf a8 [2] eb a6 [2] c0 8a [2] ee a8 [2] fa b3 [2] f5 a9 [2] eb b4 [2] e9 b5 [2] f2 b3 [2] ee b4 [2] f2 9b }

  condition:
    any of them
}