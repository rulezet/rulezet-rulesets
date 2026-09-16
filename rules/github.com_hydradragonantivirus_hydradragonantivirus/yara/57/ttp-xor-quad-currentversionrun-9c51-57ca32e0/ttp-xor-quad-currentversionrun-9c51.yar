rule TTP_XOR_QUAD_CurrentVersionRun_9c51 {
  strings:
    $key_9c51 = { cf 3e [2] eb 30 [2] c0 1c [2] ee 3e [2] fa 25 [2] f5 3f [2] eb 22 [2] e9 23 [2] f2 25 [2] ee 22 [2] f2 0d }

  condition:
    any of them
}