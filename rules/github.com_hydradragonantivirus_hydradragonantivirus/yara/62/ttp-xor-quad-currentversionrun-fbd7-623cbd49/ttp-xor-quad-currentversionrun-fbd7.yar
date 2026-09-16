rule TTP_XOR_QUAD_CurrentVersionRun_fbd7 {
  strings:
    $key_fbd7 = { a8 b8 [2] 8c b6 [2] a7 9a [2] 89 b8 [2] 9d a3 [2] 92 b9 [2] 8c a4 [2] 8e a5 [2] 95 a3 [2] 89 a4 [2] 95 8b }

  condition:
    any of them
}