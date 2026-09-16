rule TTP_XOR_QUAD_CurrentVersionRun_d0d4 {
  strings:
    $key_d0d4 = { 83 bb [2] a7 b5 [2] 8c 99 [2] a2 bb [2] b6 a0 [2] b9 ba [2] a7 a7 [2] a5 a6 [2] be a0 [2] a2 a7 [2] be 88 }

  condition:
    any of them
}