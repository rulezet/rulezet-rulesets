rule TTP_XOR_QUAD_CurrentVersionRun_63a7 {
  strings:
    $key_63a7 = { 30 c8 [2] 14 c6 [2] 3f ea [2] 11 c8 [2] 05 d3 [2] 0a c9 [2] 14 d4 [2] 16 d5 [2] 0d d3 [2] 11 d4 [2] 0d fb }

  condition:
    any of them
}