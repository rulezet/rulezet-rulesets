rule TTP_XOR_QUAD_CurrentVersionRun_50a7 {
  strings:
    $key_50a7 = { 03 c8 [2] 27 c6 [2] 0c ea [2] 22 c8 [2] 36 d3 [2] 39 c9 [2] 27 d4 [2] 25 d5 [2] 3e d3 [2] 22 d4 [2] 3e fb }

  condition:
    any of them
}