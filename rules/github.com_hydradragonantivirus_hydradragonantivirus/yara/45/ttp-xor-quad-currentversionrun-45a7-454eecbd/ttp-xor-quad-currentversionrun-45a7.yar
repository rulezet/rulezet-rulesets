rule TTP_XOR_QUAD_CurrentVersionRun_45a7 {
  strings:
    $key_45a7 = { 16 c8 [2] 32 c6 [2] 19 ea [2] 37 c8 [2] 23 d3 [2] 2c c9 [2] 32 d4 [2] 30 d5 [2] 2b d3 [2] 37 d4 [2] 2b fb }

  condition:
    any of them
}