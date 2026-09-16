rule TTP_XOR_QUAD_CurrentVersionRun_fbc8 {
  strings:
    $key_fbc8 = { a8 a7 [2] 8c a9 [2] a7 85 [2] 89 a7 [2] 9d bc [2] 92 a6 [2] 8c bb [2] 8e ba [2] 95 bc [2] 89 bb [2] 95 94 }

  condition:
    any of them
}