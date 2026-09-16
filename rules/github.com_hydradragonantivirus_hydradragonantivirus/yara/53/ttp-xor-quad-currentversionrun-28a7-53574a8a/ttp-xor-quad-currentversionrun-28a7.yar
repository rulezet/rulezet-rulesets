rule TTP_XOR_QUAD_CurrentVersionRun_28a7 {
  strings:
    $key_28a7 = { 7b c8 [2] 5f c6 [2] 74 ea [2] 5a c8 [2] 4e d3 [2] 41 c9 [2] 5f d4 [2] 5d d5 [2] 46 d3 [2] 5a d4 [2] 46 fb }

  condition:
    any of them
}