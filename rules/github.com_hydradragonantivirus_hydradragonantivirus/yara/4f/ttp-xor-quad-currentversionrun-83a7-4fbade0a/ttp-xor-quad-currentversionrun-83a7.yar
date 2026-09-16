rule TTP_XOR_QUAD_CurrentVersionRun_83a7 {
  strings:
    $key_83a7 = { d0 c8 [2] f4 c6 [2] df ea [2] f1 c8 [2] e5 d3 [2] ea c9 [2] f4 d4 [2] f6 d5 [2] ed d3 [2] f1 d4 [2] ed fb }

  condition:
    any of them
}