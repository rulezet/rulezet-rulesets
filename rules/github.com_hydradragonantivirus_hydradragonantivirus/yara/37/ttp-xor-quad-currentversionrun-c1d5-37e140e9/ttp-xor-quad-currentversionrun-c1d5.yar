rule TTP_XOR_QUAD_CurrentVersionRun_c1d5 {
  strings:
    $key_c1d5 = { 92 ba [2] b6 b4 [2] 9d 98 [2] b3 ba [2] a7 a1 [2] a8 bb [2] b6 a6 [2] b4 a7 [2] af a1 [2] b3 a6 [2] af 89 }

  condition:
    any of them
}