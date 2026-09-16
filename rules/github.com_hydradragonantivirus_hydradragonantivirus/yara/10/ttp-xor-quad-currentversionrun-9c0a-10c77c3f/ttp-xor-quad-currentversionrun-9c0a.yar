rule TTP_XOR_QUAD_CurrentVersionRun_9c0a {
  strings:
    $key_9c0a = { cf 65 [2] eb 6b [2] c0 47 [2] ee 65 [2] fa 7e [2] f5 64 [2] eb 79 [2] e9 78 [2] f2 7e [2] ee 79 [2] f2 56 }

  condition:
    any of them
}