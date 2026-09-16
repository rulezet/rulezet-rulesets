rule TTP_XOR_QUAD_CurrentVersionRun_e7d4 {
  strings:
    $key_e7d4 = { b4 bb [2] 90 b5 [2] bb 99 [2] 95 bb [2] 81 a0 [2] 8e ba [2] 90 a7 [2] 92 a6 [2] 89 a0 [2] 95 a7 [2] 89 88 }

  condition:
    any of them
}