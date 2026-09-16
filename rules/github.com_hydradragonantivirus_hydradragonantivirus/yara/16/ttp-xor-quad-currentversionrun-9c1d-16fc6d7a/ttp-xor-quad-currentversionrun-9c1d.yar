rule TTP_XOR_QUAD_CurrentVersionRun_9c1d {
  strings:
    $key_9c1d = { cf 72 [2] eb 7c [2] c0 50 [2] ee 72 [2] fa 69 [2] f5 73 [2] eb 6e [2] e9 6f [2] f2 69 [2] ee 6e [2] f2 41 }

  condition:
    any of them
}