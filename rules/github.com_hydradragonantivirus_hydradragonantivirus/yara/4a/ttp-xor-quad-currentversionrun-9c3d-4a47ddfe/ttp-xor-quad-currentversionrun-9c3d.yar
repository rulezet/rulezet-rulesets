rule TTP_XOR_QUAD_CurrentVersionRun_9c3d {
  strings:
    $key_9c3d = { cf 52 [2] eb 5c [2] c0 70 [2] ee 52 [2] fa 49 [2] f5 53 [2] eb 4e [2] e9 4f [2] f2 49 [2] ee 4e [2] f2 61 }

  condition:
    any of them
}