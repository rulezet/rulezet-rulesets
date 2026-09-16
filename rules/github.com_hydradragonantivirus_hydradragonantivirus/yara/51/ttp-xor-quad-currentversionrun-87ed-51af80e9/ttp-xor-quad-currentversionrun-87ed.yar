rule TTP_XOR_QUAD_CurrentVersionRun_87ed {
  strings:
    $key_87ed = { d4 82 [2] f0 8c [2] db a0 [2] f5 82 [2] e1 99 [2] ee 83 [2] f0 9e [2] f2 9f [2] e9 99 [2] f5 9e [2] e9 b1 }

  condition:
    any of them
}