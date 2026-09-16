rule TTP_XOR_QUAD_CurrentVersionRun_8791 {
  strings:
    $key_8791 = { d4 fe [2] f0 f0 [2] db dc [2] f5 fe [2] e1 e5 [2] ee ff [2] f0 e2 [2] f2 e3 [2] e9 e5 [2] f5 e2 [2] e9 cd }

  condition:
    any of them
}