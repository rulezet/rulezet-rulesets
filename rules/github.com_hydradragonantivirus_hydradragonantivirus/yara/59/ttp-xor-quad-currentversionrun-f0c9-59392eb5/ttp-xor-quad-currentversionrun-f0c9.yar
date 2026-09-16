rule TTP_XOR_QUAD_CurrentVersionRun_f0c9 {
  strings:
    $key_f0c9 = { a3 a6 [2] 87 a8 [2] ac 84 [2] 82 a6 [2] 96 bd [2] 99 a7 [2] 87 ba [2] 85 bb [2] 9e bd [2] 82 ba [2] 9e 95 }

  condition:
    any of them
}