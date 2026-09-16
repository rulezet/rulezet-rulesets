rule TTP_XOR_QUAD_CurrentVersionRun_9c6b {
  strings:
    $key_9c6b = { cf 04 [2] eb 0a [2] c0 26 [2] ee 04 [2] fa 1f [2] f5 05 [2] eb 18 [2] e9 19 [2] f2 1f [2] ee 18 [2] f2 37 }

  condition:
    any of them
}