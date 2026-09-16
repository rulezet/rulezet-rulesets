rule TTP_XOR_QUAD_CurrentVersionRun_64a7 {
  strings:
    $key_64a7 = { 37 c8 [2] 13 c6 [2] 38 ea [2] 16 c8 [2] 02 d3 [2] 0d c9 [2] 13 d4 [2] 11 d5 [2] 0a d3 [2] 16 d4 [2] 0a fb }

  condition:
    any of them
}