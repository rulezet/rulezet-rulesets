rule TTP_XOR_QUAD_CurrentVersionRun_9c55 {
  strings:
    $key_9c55 = { cf 3a [2] eb 34 [2] c0 18 [2] ee 3a [2] fa 21 [2] f5 3b [2] eb 26 [2] e9 27 [2] f2 21 [2] ee 26 [2] f2 09 }

  condition:
    any of them
}