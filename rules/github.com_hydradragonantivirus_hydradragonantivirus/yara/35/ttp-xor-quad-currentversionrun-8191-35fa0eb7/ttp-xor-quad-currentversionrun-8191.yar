rule TTP_XOR_QUAD_CurrentVersionRun_8191 {
  strings:
    $key_8191 = { d2 fe [2] f6 f0 [2] dd dc [2] f3 fe [2] e7 e5 [2] e8 ff [2] f6 e2 [2] f4 e3 [2] ef e5 [2] f3 e2 [2] ef cd }

  condition:
    any of them
}