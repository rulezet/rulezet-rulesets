rule TTP_XOR_QUAD_CurrentVersionRun_9c73 {
  strings:
    $key_9c73 = { cf 1c [2] eb 12 [2] c0 3e [2] ee 1c [2] fa 07 [2] f5 1d [2] eb 00 [2] e9 01 [2] f2 07 [2] ee 00 [2] f2 2f }

  condition:
    any of them
}