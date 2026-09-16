rule TTP_XOR_QUAD_CurrentVersionRun_9c50 {
  strings:
    $key_9c50 = { cf 3f [2] eb 31 [2] c0 1d [2] ee 3f [2] fa 24 [2] f5 3e [2] eb 23 [2] e9 22 [2] f2 24 [2] ee 23 [2] f2 0c }

  condition:
    any of them
}