rule TTP_XOR_QUAD_CurrentVersionRun_9c1e {
  strings:
    $key_9c1e = { cf 71 [2] eb 7f [2] c0 53 [2] ee 71 [2] fa 6a [2] f5 70 [2] eb 6d [2] e9 6c [2] f2 6a [2] ee 6d [2] f2 42 }

  condition:
    any of them
}