rule TTP_XOR_QUAD_CurrentVersionRun_5ea7 {
  strings:
    $key_5ea7 = { 0d c8 [2] 29 c6 [2] 02 ea [2] 2c c8 [2] 38 d3 [2] 37 c9 [2] 29 d4 [2] 2b d5 [2] 30 d3 [2] 2c d4 [2] 30 fb }

  condition:
    any of them
}