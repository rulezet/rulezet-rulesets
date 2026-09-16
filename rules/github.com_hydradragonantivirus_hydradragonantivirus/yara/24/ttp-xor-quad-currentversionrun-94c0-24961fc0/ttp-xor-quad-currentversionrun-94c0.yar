rule TTP_XOR_QUAD_CurrentVersionRun_94c0 {
  strings:
    $key_94c0 = { c7 af [2] e3 a1 [2] c8 8d [2] e6 af [2] f2 b4 [2] fd ae [2] e3 b3 [2] e1 b2 [2] fa b4 [2] e6 b3 [2] fa 9c }

  condition:
    any of them
}