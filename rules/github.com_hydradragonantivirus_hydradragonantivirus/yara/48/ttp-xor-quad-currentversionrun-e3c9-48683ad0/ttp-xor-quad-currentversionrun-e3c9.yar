rule TTP_XOR_QUAD_CurrentVersionRun_e3c9 {
  strings:
    $key_e3c9 = { b0 a6 [2] 94 a8 [2] bf 84 [2] 91 a6 [2] 85 bd [2] 8a a7 [2] 94 ba [2] 96 bb [2] 8d bd [2] 91 ba [2] 8d 95 }

  condition:
    any of them
}