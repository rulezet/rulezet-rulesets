rule TTP_XOR_QUAD_CurrentVersionRun_d0c8 {
  strings:
    $key_d0c8 = { 83 a7 [2] a7 a9 [2] 8c 85 [2] a2 a7 [2] b6 bc [2] b9 a6 [2] a7 bb [2] a5 ba [2] be bc [2] a2 bb [2] be 94 }

  condition:
    any of them
}