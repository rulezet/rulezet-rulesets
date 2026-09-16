rule TTP_XOR_QUAD_CurrentVersionRun_878a {
  strings:
    $key_878a = { d4 e5 [2] f0 eb [2] db c7 [2] f5 e5 [2] e1 fe [2] ee e4 [2] f0 f9 [2] f2 f8 [2] e9 fe [2] f5 f9 [2] e9 d6 }

  condition:
    any of them
}