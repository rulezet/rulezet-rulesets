rule TTP_XOR_QUAD_CurrentVersionRun_9c7f {
  strings:
    $key_9c7f = { cf 10 [2] eb 1e [2] c0 32 [2] ee 10 [2] fa 0b [2] f5 11 [2] eb 0c [2] e9 0d [2] f2 0b [2] ee 0c [2] f2 23 }

  condition:
    any of them
}