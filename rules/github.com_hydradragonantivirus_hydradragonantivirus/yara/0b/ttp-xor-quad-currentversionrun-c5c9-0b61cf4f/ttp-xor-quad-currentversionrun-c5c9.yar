rule TTP_XOR_QUAD_CurrentVersionRun_c5c9 {
  strings:
    $key_c5c9 = { 96 a6 [2] b2 a8 [2] 99 84 [2] b7 a6 [2] a3 bd [2] ac a7 [2] b2 ba [2] b0 bb [2] ab bd [2] b7 ba [2] ab 95 }

  condition:
    any of them
}