rule TTP_XOR_QUAD_CurrentVersionRun_1ea7 {
  strings:
    $key_1ea7 = { 4d c8 [2] 69 c6 [2] 42 ea [2] 6c c8 [2] 78 d3 [2] 77 c9 [2] 69 d4 [2] 6b d5 [2] 70 d3 [2] 6c d4 [2] 70 fb }

  condition:
    any of them
}