rule TTP_XOR_QUAD_CurrentVersionRun_f2d4 {
  strings:
    $key_f2d4 = { a1 bb [2] 85 b5 [2] ae 99 [2] 80 bb [2] 94 a0 [2] 9b ba [2] 85 a7 [2] 87 a6 [2] 9c a0 [2] 80 a7 [2] 9c 88 }

  condition:
    any of them
}