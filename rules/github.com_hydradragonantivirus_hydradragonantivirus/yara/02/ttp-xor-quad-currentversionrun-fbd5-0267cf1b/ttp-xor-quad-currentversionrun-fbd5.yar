rule TTP_XOR_QUAD_CurrentVersionRun_fbd5 {
  strings:
    $key_fbd5 = { a8 ba [2] 8c b4 [2] a7 98 [2] 89 ba [2] 9d a1 [2] 92 bb [2] 8c a6 [2] 8e a7 [2] 95 a1 [2] 89 a6 [2] 95 89 }

  condition:
    any of them
}