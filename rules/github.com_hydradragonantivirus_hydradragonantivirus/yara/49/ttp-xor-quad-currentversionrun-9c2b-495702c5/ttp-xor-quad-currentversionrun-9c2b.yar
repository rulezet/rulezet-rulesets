rule TTP_XOR_QUAD_CurrentVersionRun_9c2b {
  strings:
    $key_9c2b = { cf 44 [2] eb 4a [2] c0 66 [2] ee 44 [2] fa 5f [2] f5 45 [2] eb 58 [2] e9 59 [2] f2 5f [2] ee 58 [2] f2 77 }

  condition:
    any of them
}