rule TTP_XOR_QUAD_CurrentVersionRun_9cea {
  strings:
    $key_9cea = { cf 85 [2] eb 8b [2] c0 a7 [2] ee 85 [2] fa 9e [2] f5 84 [2] eb 99 [2] e9 98 [2] f2 9e [2] ee 99 [2] f2 b6 }

  condition:
    any of them
}