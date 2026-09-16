rule TTP_XOR_QUAD_CurrentVersionRun_d0c9 {
  strings:
    $key_d0c9 = { 83 a6 [2] a7 a8 [2] 8c 84 [2] a2 a6 [2] b6 bd [2] b9 a7 [2] a7 ba [2] a5 bb [2] be bd [2] a2 ba [2] be 95 }

  condition:
    any of them
}