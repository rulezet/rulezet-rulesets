rule TTP_XOR_QUAD_CurrentVersionRun_87ea {
  strings:
    $key_87ea = { d4 85 [2] f0 8b [2] db a7 [2] f5 85 [2] e1 9e [2] ee 84 [2] f0 99 [2] f2 98 [2] e9 9e [2] f5 99 [2] e9 b6 }

  condition:
    any of them
}