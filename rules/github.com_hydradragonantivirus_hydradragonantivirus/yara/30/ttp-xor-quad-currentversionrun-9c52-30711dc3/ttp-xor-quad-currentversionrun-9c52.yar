rule TTP_XOR_QUAD_CurrentVersionRun_9c52 {
  strings:
    $key_9c52 = { cf 3d [2] eb 33 [2] c0 1f [2] ee 3d [2] fa 26 [2] f5 3c [2] eb 21 [2] e9 20 [2] f2 26 [2] ee 21 [2] f2 0e }

  condition:
    any of them
}