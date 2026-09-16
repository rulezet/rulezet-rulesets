rule TTP_XOR_QUAD_CurrentVersionRun_d1c9 {
  strings:
    $key_d1c9 = { 82 a6 [2] a6 a8 [2] 8d 84 [2] a3 a6 [2] b7 bd [2] b8 a7 [2] a6 ba [2] a4 bb [2] bf bd [2] a3 ba [2] bf 95 }

  condition:
    any of them
}