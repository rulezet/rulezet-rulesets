rule TTP_XOR_QUAD_CurrentVersionRun_24a7 {
  strings:
    $key_24a7 = { 77 c8 [2] 53 c6 [2] 78 ea [2] 56 c8 [2] 42 d3 [2] 4d c9 [2] 53 d4 [2] 51 d5 [2] 4a d3 [2] 56 d4 [2] 4a fb }

  condition:
    any of them
}