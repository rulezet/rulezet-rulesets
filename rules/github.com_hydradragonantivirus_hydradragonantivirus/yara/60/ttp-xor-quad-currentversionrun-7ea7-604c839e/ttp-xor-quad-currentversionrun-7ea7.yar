rule TTP_XOR_QUAD_CurrentVersionRun_7ea7 {
  strings:
    $key_7ea7 = { 2d c8 [2] 09 c6 [2] 22 ea [2] 0c c8 [2] 18 d3 [2] 17 c9 [2] 09 d4 [2] 0b d5 [2] 10 d3 [2] 0c d4 [2] 10 fb }

  condition:
    any of them
}