rule TTP_XOR_QUAD_CurrentVersionRun_9c4d {
  strings:
    $key_9c4d = { cf 22 [2] eb 2c [2] c0 00 [2] ee 22 [2] fa 39 [2] f5 23 [2] eb 3e [2] e9 3f [2] f2 39 [2] ee 3e [2] f2 11 }

  condition:
    any of them
}