rule TTP_XOR_QUAD_CurrentVersionRun_87e0 {
  strings:
    $key_87e0 = { d4 8f [2] f0 81 [2] db ad [2] f5 8f [2] e1 94 [2] ee 8e [2] f0 93 [2] f2 92 [2] e9 94 [2] f5 93 [2] e9 bc }

  condition:
    any of them
}