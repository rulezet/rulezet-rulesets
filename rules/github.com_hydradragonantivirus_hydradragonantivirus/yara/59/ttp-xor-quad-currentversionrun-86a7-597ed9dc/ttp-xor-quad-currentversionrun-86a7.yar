rule TTP_XOR_QUAD_CurrentVersionRun_86a7 {
  strings:
    $key_86a7 = { d5 c8 [2] f1 c6 [2] da ea [2] f4 c8 [2] e0 d3 [2] ef c9 [2] f1 d4 [2] f3 d5 [2] e8 d3 [2] f4 d4 [2] e8 fb }

  condition:
    any of them
}