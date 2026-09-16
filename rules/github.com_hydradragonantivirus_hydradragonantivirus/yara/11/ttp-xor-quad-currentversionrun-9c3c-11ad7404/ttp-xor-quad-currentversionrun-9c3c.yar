rule TTP_XOR_QUAD_CurrentVersionRun_9c3c {
  strings:
    $key_9c3c = { cf 53 [2] eb 5d [2] c0 71 [2] ee 53 [2] fa 48 [2] f5 52 [2] eb 4f [2] e9 4e [2] f2 48 [2] ee 4f [2] f2 60 }

  condition:
    any of them
}