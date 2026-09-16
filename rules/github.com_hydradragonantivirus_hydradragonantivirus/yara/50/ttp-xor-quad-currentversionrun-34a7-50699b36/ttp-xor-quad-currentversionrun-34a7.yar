rule TTP_XOR_QUAD_CurrentVersionRun_34a7 {
  strings:
    $key_34a7 = { 67 c8 [2] 43 c6 [2] 68 ea [2] 46 c8 [2] 52 d3 [2] 5d c9 [2] 43 d4 [2] 41 d5 [2] 5a d3 [2] 46 d4 [2] 5a fb }

  condition:
    any of them
}