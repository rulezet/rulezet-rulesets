rule TTP_XOR_QUAD_CurrentVersionRun_d7c8 {
  strings:
    $key_d7c8 = { 84 a7 [2] a0 a9 [2] 8b 85 [2] a5 a7 [2] b1 bc [2] be a6 [2] a0 bb [2] a2 ba [2] b9 bc [2] a5 bb [2] b9 94 }

  condition:
    any of them
}