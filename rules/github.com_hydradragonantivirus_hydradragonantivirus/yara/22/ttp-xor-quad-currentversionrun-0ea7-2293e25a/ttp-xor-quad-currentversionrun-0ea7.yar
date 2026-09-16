rule TTP_XOR_QUAD_CurrentVersionRun_0ea7 {
  strings:
    $key_0ea7 = { 5d c8 [2] 79 c6 [2] 52 ea [2] 7c c8 [2] 68 d3 [2] 67 c9 [2] 79 d4 [2] 7b d5 [2] 60 d3 [2] 7c d4 [2] 60 fb }

  condition:
    any of them
}