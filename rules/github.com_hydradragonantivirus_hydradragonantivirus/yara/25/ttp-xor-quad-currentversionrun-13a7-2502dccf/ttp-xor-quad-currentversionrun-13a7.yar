rule TTP_XOR_QUAD_CurrentVersionRun_13a7 {
  strings:
    $key_13a7 = { 40 c8 [2] 64 c6 [2] 4f ea [2] 61 c8 [2] 75 d3 [2] 7a c9 [2] 64 d4 [2] 66 d5 [2] 7d d3 [2] 61 d4 [2] 7d fb }

  condition:
    any of them
}