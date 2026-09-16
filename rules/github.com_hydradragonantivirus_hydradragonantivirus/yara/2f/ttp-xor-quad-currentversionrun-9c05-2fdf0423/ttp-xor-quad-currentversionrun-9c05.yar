rule TTP_XOR_QUAD_CurrentVersionRun_9c05 {
  strings:
    $key_9c05 = { cf 6a [2] eb 64 [2] c0 48 [2] ee 6a [2] fa 71 [2] f5 6b [2] eb 76 [2] e9 77 [2] f2 71 [2] ee 76 [2] f2 59 }

  condition:
    any of them
}