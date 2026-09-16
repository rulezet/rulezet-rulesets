rule TTP_XOR_QUAD_CurrentVersionRun_9a8d {
  strings:
    $key_9a8d = { c9 e2 [2] ed ec [2] c6 c0 [2] e8 e2 [2] fc f9 [2] f3 e3 [2] ed fe [2] ef ff [2] f4 f9 [2] e8 fe [2] f4 d1 }

  condition:
    any of them
}