rule TTP_XOR_QUAD_CurrentVersionRun_83b5 {
  strings:
    $key_83b5 = { d0 da [2] f4 d4 [2] df f8 [2] f1 da [2] e5 c1 [2] ea db [2] f4 c6 [2] f6 c7 [2] ed c1 [2] f1 c6 [2] ed e9 }

  condition:
    any of them
}