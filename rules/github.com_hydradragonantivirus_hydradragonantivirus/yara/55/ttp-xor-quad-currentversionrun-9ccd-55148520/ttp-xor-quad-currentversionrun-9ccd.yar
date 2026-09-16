rule TTP_XOR_QUAD_CurrentVersionRun_9ccd {
  strings:
    $key_9ccd = { cf a2 [2] eb ac [2] c0 80 [2] ee a2 [2] fa b9 [2] f5 a3 [2] eb be [2] e9 bf [2] f2 b9 [2] ee be [2] f2 91 }

  condition:
    any of them
}