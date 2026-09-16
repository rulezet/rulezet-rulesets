rule TTP_XOR_QUAD_CurrentVersionRun_868d {
  strings:
    $key_868d = { d5 e2 [2] f1 ec [2] da c0 [2] f4 e2 [2] e0 f9 [2] ef e3 [2] f1 fe [2] f3 ff [2] e8 f9 [2] f4 fe [2] e8 d1 }

  condition:
    any of them
}