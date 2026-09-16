rule TTP_XOR_QUAD_CurrentVersionRun_83b4 {
  strings:
    $key_83b4 = { d0 db [2] f4 d5 [2] df f9 [2] f1 db [2] e5 c0 [2] ea da [2] f4 c7 [2] f6 c6 [2] ed c0 [2] f1 c7 [2] ed e8 }

  condition:
    any of them
}