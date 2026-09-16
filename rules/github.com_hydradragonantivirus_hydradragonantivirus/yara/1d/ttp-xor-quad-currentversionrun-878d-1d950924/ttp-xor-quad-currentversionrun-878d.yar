rule TTP_XOR_QUAD_CurrentVersionRun_878d {
  strings:
    $key_878d = { d4 e2 [2] f0 ec [2] db c0 [2] f5 e2 [2] e1 f9 [2] ee e3 [2] f0 fe [2] f2 ff [2] e9 f9 [2] f5 fe [2] e9 d1 }

  condition:
    any of them
}