rule TTP_XOR_QUAD_CurrentVersionRun_c5c8 {
  strings:
    $key_c5c8 = { 96 a7 [2] b2 a9 [2] 99 85 [2] b7 a7 [2] a3 bc [2] ac a6 [2] b2 bb [2] b0 ba [2] ab bc [2] b7 bb [2] ab 94 }

  condition:
    any of them
}