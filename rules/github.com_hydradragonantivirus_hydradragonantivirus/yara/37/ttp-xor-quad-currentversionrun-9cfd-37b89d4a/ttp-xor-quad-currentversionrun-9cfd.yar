rule TTP_XOR_QUAD_CurrentVersionRun_9cfd {
  strings:
    $key_9cfd = { cf 92 [2] eb 9c [2] c0 b0 [2] ee 92 [2] fa 89 [2] f5 93 [2] eb 8e [2] e9 8f [2] f2 89 [2] ee 8e [2] f2 a1 }

  condition:
    any of them
}