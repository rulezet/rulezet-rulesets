rule TTP_XOR_QUAD_CurrentVersionRun_f6a7 {
  strings:
    $key_f6a7 = { a5 c8 [2] 81 c6 [2] aa ea [2] 84 c8 [2] 90 d3 [2] 9f c9 [2] 81 d4 [2] 83 d5 [2] 98 d3 [2] 84 d4 [2] 98 fb }

  condition:
    any of them
}