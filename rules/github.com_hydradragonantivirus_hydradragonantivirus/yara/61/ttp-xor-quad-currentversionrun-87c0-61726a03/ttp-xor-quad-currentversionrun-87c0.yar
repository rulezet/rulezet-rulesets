rule TTP_XOR_QUAD_CurrentVersionRun_87c0 {
  strings:
    $key_87c0 = { d4 af [2] f0 a1 [2] db 8d [2] f5 af [2] e1 b4 [2] ee ae [2] f0 b3 [2] f2 b2 [2] e9 b4 [2] f5 b3 [2] e9 9c }

  condition:
    any of them
}