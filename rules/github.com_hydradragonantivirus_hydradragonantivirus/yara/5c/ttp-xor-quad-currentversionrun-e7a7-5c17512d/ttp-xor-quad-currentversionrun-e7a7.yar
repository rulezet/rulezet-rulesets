rule TTP_XOR_QUAD_CurrentVersionRun_e7a7 {
  strings:
    $key_e7a7 = { b4 c8 [2] 90 c6 [2] bb ea [2] 95 c8 [2] 81 d3 [2] 8e c9 [2] 90 d4 [2] 92 d5 [2] 89 d3 [2] 95 d4 [2] 89 fb }

  condition:
    any of them
}