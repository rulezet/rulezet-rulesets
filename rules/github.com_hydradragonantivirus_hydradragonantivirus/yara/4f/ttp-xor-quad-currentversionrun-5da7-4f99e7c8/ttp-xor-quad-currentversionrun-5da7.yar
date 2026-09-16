rule TTP_XOR_QUAD_CurrentVersionRun_5da7 {
  strings:
    $key_5da7 = { 0e c8 [2] 2a c6 [2] 01 ea [2] 2f c8 [2] 3b d3 [2] 34 c9 [2] 2a d4 [2] 28 d5 [2] 33 d3 [2] 2f d4 [2] 33 fb }

  condition:
    any of them
}