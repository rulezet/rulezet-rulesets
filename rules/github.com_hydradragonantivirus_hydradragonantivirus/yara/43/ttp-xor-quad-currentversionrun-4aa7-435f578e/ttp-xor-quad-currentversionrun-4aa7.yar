rule TTP_XOR_QUAD_CurrentVersionRun_4aa7 {
  strings:
    $key_4aa7 = { 19 c8 [2] 3d c6 [2] 16 ea [2] 38 c8 [2] 2c d3 [2] 23 c9 [2] 3d d4 [2] 3f d5 [2] 24 d3 [2] 38 d4 [2] 24 fb }

  condition:
    any of them
}