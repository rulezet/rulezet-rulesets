rule TTP_XOR_QUAD_CurrentVersionRun_44c9 {
  strings:
    $key_44c9 = { 17 a6 [2] 33 a8 [2] 18 84 [2] 36 a6 [2] 22 bd [2] 2d a7 [2] 33 ba [2] 31 bb [2] 2a bd [2] 36 ba [2] 2a 95 }

  condition:
    any of them
}