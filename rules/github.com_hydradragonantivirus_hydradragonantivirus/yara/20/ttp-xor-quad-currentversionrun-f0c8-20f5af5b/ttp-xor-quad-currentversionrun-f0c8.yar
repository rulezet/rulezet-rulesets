rule TTP_XOR_QUAD_CurrentVersionRun_f0c8 {
  strings:
    $key_f0c8 = { a3 a7 [2] 87 a9 [2] ac 85 [2] 82 a7 [2] 96 bc [2] 99 a6 [2] 87 bb [2] 85 ba [2] 9e bc [2] 82 bb [2] 9e 94 }

  condition:
    any of them
}