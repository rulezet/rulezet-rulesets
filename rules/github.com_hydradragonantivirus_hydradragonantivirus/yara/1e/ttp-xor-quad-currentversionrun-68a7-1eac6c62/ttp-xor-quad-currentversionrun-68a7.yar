rule TTP_XOR_QUAD_CurrentVersionRun_68a7 {
  strings:
    $key_68a7 = { 3b c8 [2] 1f c6 [2] 34 ea [2] 1a c8 [2] 0e d3 [2] 01 c9 [2] 1f d4 [2] 1d d5 [2] 06 d3 [2] 1a d4 [2] 06 fb }

  condition:
    any of them
}