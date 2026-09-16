rule TTP_XOR_QUAD_CurrentVersionRun_c0c9 {
  strings:
    $key_c0c9 = { 93 a6 [2] b7 a8 [2] 9c 84 [2] b2 a6 [2] a6 bd [2] a9 a7 [2] b7 ba [2] b5 bb [2] ae bd [2] b2 ba [2] ae 95 }

  condition:
    any of them
}