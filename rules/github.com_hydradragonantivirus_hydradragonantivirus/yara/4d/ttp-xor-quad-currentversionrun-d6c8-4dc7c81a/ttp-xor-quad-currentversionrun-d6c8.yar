rule TTP_XOR_QUAD_CurrentVersionRun_d6c8 {
  strings:
    $key_d6c8 = { 85 a7 [2] a1 a9 [2] 8a 85 [2] a4 a7 [2] b0 bc [2] bf a6 [2] a1 bb [2] a3 ba [2] b8 bc [2] a4 bb [2] b8 94 }

  condition:
    any of them
}