rule TTP_XOR_QUAD_CurrentVersionRun_18a7 {
  strings:
    $key_18a7 = { 4b c8 [2] 6f c6 [2] 44 ea [2] 6a c8 [2] 7e d3 [2] 71 c9 [2] 6f d4 [2] 6d d5 [2] 76 d3 [2] 6a d4 [2] 76 fb }

  condition:
    any of them
}