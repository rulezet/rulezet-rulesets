rule TTP_XOR_QUAD_CurrentVersionRun_87a6 {
  strings:
    $key_87a6 = { d4 c9 [2] f0 c7 [2] db eb [2] f5 c9 [2] e1 d2 [2] ee c8 [2] f0 d5 [2] f2 d4 [2] e9 d2 [2] f5 d5 [2] e9 fa }

  condition:
    any of them
}