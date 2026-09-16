rule TTP_XOR_QUAD_CurrentVersionRun_c7c8 {
  strings:
    $key_c7c8 = { 94 a7 [2] b0 a9 [2] 9b 85 [2] b5 a7 [2] a1 bc [2] ae a6 [2] b0 bb [2] b2 ba [2] a9 bc [2] b5 bb [2] a9 94 }

  condition:
    any of them
}