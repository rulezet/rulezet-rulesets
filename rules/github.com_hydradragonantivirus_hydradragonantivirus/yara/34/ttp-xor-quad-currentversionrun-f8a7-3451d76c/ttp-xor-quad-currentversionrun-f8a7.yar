rule TTP_XOR_QUAD_CurrentVersionRun_f8a7 {
  strings:
    $key_f8a7 = { ab c8 [2] 8f c6 [2] a4 ea [2] 8a c8 [2] 9e d3 [2] 91 c9 [2] 8f d4 [2] 8d d5 [2] 96 d3 [2] 8a d4 [2] 96 fb }

  condition:
    any of them
}