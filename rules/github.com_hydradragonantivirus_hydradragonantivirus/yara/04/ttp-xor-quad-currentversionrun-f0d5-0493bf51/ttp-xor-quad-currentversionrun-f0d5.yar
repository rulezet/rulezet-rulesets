rule TTP_XOR_QUAD_CurrentVersionRun_f0d5 {
  strings:
    $key_f0d5 = { a3 ba [2] 87 b4 [2] ac 98 [2] 82 ba [2] 96 a1 [2] 99 bb [2] 87 a6 [2] 85 a7 [2] 9e a1 [2] 82 a6 [2] 9e 89 }

  condition:
    any of them
}