rule TTP_XOR_QUAD_CurrentVersionRun_eba7 {
  strings:
    $key_eba7 = { b8 c8 [2] 9c c6 [2] b7 ea [2] 99 c8 [2] 8d d3 [2] 82 c9 [2] 9c d4 [2] 9e d5 [2] 85 d3 [2] 99 d4 [2] 85 fb }

  condition:
    any of them
}