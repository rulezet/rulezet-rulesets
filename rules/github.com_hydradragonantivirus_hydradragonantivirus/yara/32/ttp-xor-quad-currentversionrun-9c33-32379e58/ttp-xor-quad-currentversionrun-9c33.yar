rule TTP_XOR_QUAD_CurrentVersionRun_9c33 {
  strings:
    $key_9c33 = { cf 5c [2] eb 52 [2] c0 7e [2] ee 5c [2] fa 47 [2] f5 5d [2] eb 40 [2] e9 41 [2] f2 47 [2] ee 40 [2] f2 6f }

  condition:
    any of them
}