rule TTP_XOR_QUAD_CurrentVersionRun_9c19 {
  strings:
    $key_9c19 = { cf 76 [2] eb 78 [2] c0 54 [2] ee 76 [2] fa 6d [2] f5 77 [2] eb 6a [2] e9 6b [2] f2 6d [2] ee 6a [2] f2 45 }

  condition:
    any of them
}