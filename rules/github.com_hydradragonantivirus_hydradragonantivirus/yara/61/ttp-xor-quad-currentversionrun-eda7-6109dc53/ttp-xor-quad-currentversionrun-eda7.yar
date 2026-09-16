rule TTP_XOR_QUAD_CurrentVersionRun_eda7 {
  strings:
    $key_eda7 = { be c8 [2] 9a c6 [2] b1 ea [2] 9f c8 [2] 8b d3 [2] 84 c9 [2] 9a d4 [2] 98 d5 [2] 83 d3 [2] 9f d4 [2] 83 fb }

  condition:
    any of them
}