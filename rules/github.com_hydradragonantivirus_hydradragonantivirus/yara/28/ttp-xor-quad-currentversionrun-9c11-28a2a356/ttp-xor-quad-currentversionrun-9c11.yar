rule TTP_XOR_QUAD_CurrentVersionRun_9c11 {
  strings:
    $key_9c11 = { cf 7e [2] eb 70 [2] c0 5c [2] ee 7e [2] fa 65 [2] f5 7f [2] eb 62 [2] e9 63 [2] f2 65 [2] ee 62 [2] f2 4d }

  condition:
    any of them
}