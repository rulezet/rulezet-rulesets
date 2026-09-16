rule TTP_XOR_QUAD_CurrentVersionRun_d8a7 {
  strings:
    $key_d8a7 = { 8b c8 [2] af c6 [2] 84 ea [2] aa c8 [2] be d3 [2] b1 c9 [2] af d4 [2] ad d5 [2] b6 d3 [2] aa d4 [2] b6 fb }

  condition:
    any of them
}