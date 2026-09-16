rule TTP_XOR_QUAD_CurrentVersionRun_87fd {
  strings:
    $key_87fd = { d4 92 [2] f0 9c [2] db b0 [2] f5 92 [2] e1 89 [2] ee 93 [2] f0 8e [2] f2 8f [2] e9 89 [2] f5 8e [2] e9 a1 }

  condition:
    any of them
}