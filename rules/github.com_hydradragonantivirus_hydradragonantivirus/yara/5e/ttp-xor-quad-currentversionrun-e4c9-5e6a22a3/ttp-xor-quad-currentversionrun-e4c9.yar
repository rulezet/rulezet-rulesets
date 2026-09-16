rule TTP_XOR_QUAD_CurrentVersionRun_e4c9 {
  strings:
    $key_e4c9 = { b7 a6 [2] 93 a8 [2] b8 84 [2] 96 a6 [2] 82 bd [2] 8d a7 [2] 93 ba [2] 91 bb [2] 8a bd [2] 96 ba [2] 8a 95 }

  condition:
    any of them
}