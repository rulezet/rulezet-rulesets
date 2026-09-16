rule TTP_XOR_QUAD_CurrentVersionRun_9c4c {
  strings:
    $key_9c4c = { cf 23 [2] eb 2d [2] c0 01 [2] ee 23 [2] fa 38 [2] f5 22 [2] eb 3f [2] e9 3e [2] f2 38 [2] ee 3f [2] f2 10 }

  condition:
    any of them
}