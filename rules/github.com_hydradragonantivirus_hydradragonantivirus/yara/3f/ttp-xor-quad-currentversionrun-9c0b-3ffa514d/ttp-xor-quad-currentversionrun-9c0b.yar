rule TTP_XOR_QUAD_CurrentVersionRun_9c0b {
  strings:
    $key_9c0b = { cf 64 [2] eb 6a [2] c0 46 [2] ee 64 [2] fa 7f [2] f5 65 [2] eb 78 [2] e9 79 [2] f2 7f [2] ee 78 [2] f2 57 }

  condition:
    any of them
}