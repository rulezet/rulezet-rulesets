rule TTP_XOR_QUAD_CurrentVersionRun_d6d4 {
  strings:
    $key_d6d4 = { 85 bb [2] a1 b5 [2] 8a 99 [2] a4 bb [2] b0 a0 [2] bf ba [2] a1 a7 [2] a3 a6 [2] b8 a0 [2] a4 a7 [2] b8 88 }

  condition:
    any of them
}