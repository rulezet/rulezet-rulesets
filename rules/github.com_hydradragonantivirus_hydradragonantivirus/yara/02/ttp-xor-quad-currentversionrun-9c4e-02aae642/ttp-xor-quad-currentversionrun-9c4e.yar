rule TTP_XOR_QUAD_CurrentVersionRun_9c4e {
  strings:
    $key_9c4e = { cf 21 [2] eb 2f [2] c0 03 [2] ee 21 [2] fa 3a [2] f5 20 [2] eb 3d [2] e9 3c [2] f2 3a [2] ee 3d [2] f2 12 }

  condition:
    any of them
}