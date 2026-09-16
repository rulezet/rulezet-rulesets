rule TTP_XOR_QUAD_CurrentVersionRun_9c71 {
  strings:
    $key_9c71 = { cf 1e [2] eb 10 [2] c0 3c [2] ee 1e [2] fa 05 [2] f5 1f [2] eb 02 [2] e9 03 [2] f2 05 [2] ee 02 [2] f2 2d }

  condition:
    any of them
}