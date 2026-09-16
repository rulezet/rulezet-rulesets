rule TTP_XOR_QUAD_CurrentVersionRun_9c61 {
  strings:
    $key_9c61 = { cf 0e [2] eb 00 [2] c0 2c [2] ee 0e [2] fa 15 [2] f5 0f [2] eb 12 [2] e9 13 [2] f2 15 [2] ee 12 [2] f2 3d }

  condition:
    any of them
}