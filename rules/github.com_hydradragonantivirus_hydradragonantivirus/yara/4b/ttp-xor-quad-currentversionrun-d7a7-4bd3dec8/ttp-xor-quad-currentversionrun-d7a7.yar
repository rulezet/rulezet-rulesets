rule TTP_XOR_QUAD_CurrentVersionRun_d7a7 {
  strings:
    $key_d7a7 = { 84 c8 [2] a0 c6 [2] 8b ea [2] a5 c8 [2] b1 d3 [2] be c9 [2] a0 d4 [2] a2 d5 [2] b9 d3 [2] a5 d4 [2] b9 fb }

  condition:
    any of them
}