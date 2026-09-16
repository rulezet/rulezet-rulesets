rule TTP_XOR_QUAD_CurrentVersionRun_dda7 {
  strings:
    $key_dda7 = { 8e c8 [2] aa c6 [2] 81 ea [2] af c8 [2] bb d3 [2] b4 c9 [2] aa d4 [2] a8 d5 [2] b3 d3 [2] af d4 [2] b3 fb }

  condition:
    any of them
}