rule TTP_XOR_QUAD_CurrentVersionRun_c4c8 {
  strings:
    $key_c4c8 = { 97 a7 [2] b3 a9 [2] 98 85 [2] b6 a7 [2] a2 bc [2] ad a6 [2] b3 bb [2] b1 ba [2] aa bc [2] b6 bb [2] aa 94 }

  condition:
    any of them
}