rule TTP_XOR_QUAD_CurrentVersionRun_9c7b {
  strings:
    $key_9c7b = { cf 14 [2] eb 1a [2] c0 36 [2] ee 14 [2] fa 0f [2] f5 15 [2] eb 08 [2] e9 09 [2] f2 0f [2] ee 08 [2] f2 27 }

  condition:
    any of them
}