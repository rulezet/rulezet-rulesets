rule TTP_XOR_QUAD_CurrentVersionRun_9cf9 {
  strings:
    $key_9cf9 = { cf 96 [2] eb 98 [2] c0 b4 [2] ee 96 [2] fa 8d [2] f5 97 [2] eb 8a [2] e9 8b [2] f2 8d [2] ee 8a [2] f2 a5 }

  condition:
    any of them
}