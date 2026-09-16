rule TTP_XOR_QUAD_CurrentVersionRun_87ec {
  strings:
    $key_87ec = { d4 83 [2] f0 8d [2] db a1 [2] f5 83 [2] e1 98 [2] ee 82 [2] f0 9f [2] f2 9e [2] e9 98 [2] f5 9f [2] e9 b0 }

  condition:
    any of them
}