rule TTP_XOR_QUAD_CurrentVersionRun_53a7 {
  strings:
    $key_53a7 = { 00 c8 [2] 24 c6 [2] 0f ea [2] 21 c8 [2] 35 d3 [2] 3a c9 [2] 24 d4 [2] 26 d5 [2] 3d d3 [2] 21 d4 [2] 3d fb }

  condition:
    any of them
}