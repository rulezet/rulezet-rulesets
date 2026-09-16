rule TTP_XOR_QUAD_CurrentVersionRun_9cd1 {
  strings:
    $key_9cd1 = { cf be [2] eb b0 [2] c0 9c [2] ee be [2] fa a5 [2] f5 bf [2] eb a2 [2] e9 a3 [2] f2 a5 [2] ee a2 [2] f2 8d }

  condition:
    any of them
}