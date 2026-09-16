rule TTP_XOR_QUAD_CurrentVersionRun_43c9 {
  strings:
    $key_43c9 = { 10 a6 [2] 34 a8 [2] 1f 84 [2] 31 a6 [2] 25 bd [2] 2a a7 [2] 34 ba [2] 36 bb [2] 2d bd [2] 31 ba [2] 2d 95 }

  condition:
    any of them
}