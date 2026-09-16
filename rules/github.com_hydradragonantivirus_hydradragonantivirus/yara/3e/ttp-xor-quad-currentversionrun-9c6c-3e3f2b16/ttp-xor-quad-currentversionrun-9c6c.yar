rule TTP_XOR_QUAD_CurrentVersionRun_9c6c {
  strings:
    $key_9c6c = { cf 03 [2] eb 0d [2] c0 21 [2] ee 03 [2] fa 18 [2] f5 02 [2] eb 1f [2] e9 1e [2] f2 18 [2] ee 1f [2] f2 30 }

  condition:
    any of them
}