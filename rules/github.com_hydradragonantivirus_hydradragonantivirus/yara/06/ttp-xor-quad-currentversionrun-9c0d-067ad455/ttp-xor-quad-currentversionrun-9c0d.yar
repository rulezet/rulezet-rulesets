rule TTP_XOR_QUAD_CurrentVersionRun_9c0d {
  strings:
    $key_9c0d = { cf 62 [2] eb 6c [2] c0 40 [2] ee 62 [2] fa 79 [2] f5 63 [2] eb 7e [2] e9 7f [2] f2 79 [2] ee 7e [2] f2 51 }

  condition:
    any of them
}