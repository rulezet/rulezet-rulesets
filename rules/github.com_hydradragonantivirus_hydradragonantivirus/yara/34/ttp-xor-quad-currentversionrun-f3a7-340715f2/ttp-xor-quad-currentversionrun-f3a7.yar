rule TTP_XOR_QUAD_CurrentVersionRun_f3a7 {
  strings:
    $key_f3a7 = { a0 c8 [2] 84 c6 [2] af ea [2] 81 c8 [2] 95 d3 [2] 9a c9 [2] 84 d4 [2] 86 d5 [2] 9d d3 [2] 81 d4 [2] 9d fb }

  condition:
    any of them
}