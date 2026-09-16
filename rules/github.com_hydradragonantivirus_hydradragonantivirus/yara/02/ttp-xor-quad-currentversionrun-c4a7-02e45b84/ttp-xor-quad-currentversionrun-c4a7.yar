rule TTP_XOR_QUAD_CurrentVersionRun_c4a7 {
  strings:
    $key_c4a7 = { 97 c8 [2] b3 c6 [2] 98 ea [2] b6 c8 [2] a2 d3 [2] ad c9 [2] b3 d4 [2] b1 d5 [2] aa d3 [2] b6 d4 [2] aa fb }

  condition:
    any of them
}