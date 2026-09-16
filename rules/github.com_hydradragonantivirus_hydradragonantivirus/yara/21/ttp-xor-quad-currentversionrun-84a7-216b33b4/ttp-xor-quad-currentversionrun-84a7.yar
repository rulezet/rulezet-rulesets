rule TTP_XOR_QUAD_CurrentVersionRun_84a7 {
  strings:
    $key_84a7 = { d7 c8 [2] f3 c6 [2] d8 ea [2] f6 c8 [2] e2 d3 [2] ed c9 [2] f3 d4 [2] f1 d5 [2] ea d3 [2] f6 d4 [2] ea fb }

  condition:
    any of them
}