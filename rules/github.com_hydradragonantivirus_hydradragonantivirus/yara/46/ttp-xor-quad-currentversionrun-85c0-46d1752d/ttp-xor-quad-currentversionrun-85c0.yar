rule TTP_XOR_QUAD_CurrentVersionRun_85c0 {
  strings:
    $key_85c0 = { d6 af [2] f2 a1 [2] d9 8d [2] f7 af [2] e3 b4 [2] ec ae [2] f2 b3 [2] f0 b2 [2] eb b4 [2] f7 b3 [2] eb 9c }

  condition:
    any of them
}