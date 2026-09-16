rule TTP_XOR_QUAD_CurrentVersionRun_0ba7 {
  strings:
    $key_0ba7 = { 58 c8 [2] 7c c6 [2] 57 ea [2] 79 c8 [2] 6d d3 [2] 62 c9 [2] 7c d4 [2] 7e d5 [2] 65 d3 [2] 79 d4 [2] 65 fb }

  condition:
    any of them
}