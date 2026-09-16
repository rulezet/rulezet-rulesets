rule TTP_XOR_QUAD_CurrentVersionRun_9c7a {
  strings:
    $key_9c7a = { cf 15 [2] eb 1b [2] c0 37 [2] ee 15 [2] fa 0e [2] f5 14 [2] eb 09 [2] e9 08 [2] f2 0e [2] ee 09 [2] f2 26 }

  condition:
    any of them
}