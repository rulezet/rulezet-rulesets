rule TTP_XOR_QUAD_CurrentVersionRun_84c0 {
  strings:
    $key_84c0 = { d7 af [2] f3 a1 [2] d8 8d [2] f6 af [2] e2 b4 [2] ed ae [2] f3 b3 [2] f1 b2 [2] ea b4 [2] f6 b3 [2] ea 9c }

  condition:
    any of them
}