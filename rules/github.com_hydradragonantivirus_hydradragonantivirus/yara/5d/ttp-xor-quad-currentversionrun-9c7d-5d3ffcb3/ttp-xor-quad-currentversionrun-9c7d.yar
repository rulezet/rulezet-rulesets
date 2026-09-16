rule TTP_XOR_QUAD_CurrentVersionRun_9c7d {
  strings:
    $key_9c7d = { cf 12 [2] eb 1c [2] c0 30 [2] ee 12 [2] fa 09 [2] f5 13 [2] eb 0e [2] e9 0f [2] f2 09 [2] ee 0e [2] f2 21 }

  condition:
    any of them
}