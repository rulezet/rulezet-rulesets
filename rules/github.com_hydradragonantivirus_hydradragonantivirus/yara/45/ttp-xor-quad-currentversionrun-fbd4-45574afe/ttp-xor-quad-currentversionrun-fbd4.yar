rule TTP_XOR_QUAD_CurrentVersionRun_fbd4 {
  strings:
    $key_fbd4 = { a8 bb [2] 8c b5 [2] a7 99 [2] 89 bb [2] 9d a0 [2] 92 ba [2] 8c a7 [2] 8e a6 [2] 95 a0 [2] 89 a7 [2] 95 88 }

  condition:
    any of them
}