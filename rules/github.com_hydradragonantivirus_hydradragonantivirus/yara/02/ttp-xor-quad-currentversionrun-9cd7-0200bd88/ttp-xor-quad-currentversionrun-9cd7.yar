rule TTP_XOR_QUAD_CurrentVersionRun_9cd7 {
  strings:
    $key_9cd7 = { cf b8 [2] eb b6 [2] c0 9a [2] ee b8 [2] fa a3 [2] f5 b9 [2] eb a4 [2] e9 a5 [2] f2 a3 [2] ee a4 [2] f2 8b }

  condition:
    any of them
}