rule TTP_XOR_QUAD_CurrentVersionRun_04c9 {
  strings:
    $key_04c9 = { 57 a6 [2] 73 a8 [2] 58 84 [2] 76 a6 [2] 62 bd [2] 6d a7 [2] 73 ba [2] 71 bb [2] 6a bd [2] 76 ba [2] 6a 95 }

  condition:
    any of them
}