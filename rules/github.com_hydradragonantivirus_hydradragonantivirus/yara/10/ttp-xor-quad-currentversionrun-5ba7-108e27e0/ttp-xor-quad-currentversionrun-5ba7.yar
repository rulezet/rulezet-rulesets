rule TTP_XOR_QUAD_CurrentVersionRun_5ba7 {
  strings:
    $key_5ba7 = { 08 c8 [2] 2c c6 [2] 07 ea [2] 29 c8 [2] 3d d3 [2] 32 c9 [2] 2c d4 [2] 2e d5 [2] 35 d3 [2] 29 d4 [2] 35 fb }

  condition:
    any of them
}