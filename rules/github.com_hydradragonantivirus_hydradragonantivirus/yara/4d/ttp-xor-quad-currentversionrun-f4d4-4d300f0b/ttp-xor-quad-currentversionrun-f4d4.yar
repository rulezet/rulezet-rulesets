rule TTP_XOR_QUAD_CurrentVersionRun_f4d4 {
  strings:
    $key_f4d4 = { a7 bb [2] 83 b5 [2] a8 99 [2] 86 bb [2] 92 a0 [2] 9d ba [2] 83 a7 [2] 81 a6 [2] 9a a0 [2] 86 a7 [2] 9a 88 }

  condition:
    any of them
}