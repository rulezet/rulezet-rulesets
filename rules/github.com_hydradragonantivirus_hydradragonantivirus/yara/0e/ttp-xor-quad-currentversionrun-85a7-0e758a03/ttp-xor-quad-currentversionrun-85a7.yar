rule TTP_XOR_QUAD_CurrentVersionRun_85a7 {
  strings:
    $key_85a7 = { d6 c8 [2] f2 c6 [2] d9 ea [2] f7 c8 [2] e3 d3 [2] ec c9 [2] f2 d4 [2] f0 d5 [2] eb d3 [2] f7 d4 [2] eb fb }

  condition:
    any of them
}