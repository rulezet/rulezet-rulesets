rule TTP_XOR_QUAD_CurrentVersionRun_d4c8 {
  strings:
    $key_d4c8 = { 87 a7 [2] a3 a9 [2] 88 85 [2] a6 a7 [2] b2 bc [2] bd a6 [2] a3 bb [2] a1 ba [2] ba bc [2] a6 bb [2] ba 94 }

  condition:
    any of them
}