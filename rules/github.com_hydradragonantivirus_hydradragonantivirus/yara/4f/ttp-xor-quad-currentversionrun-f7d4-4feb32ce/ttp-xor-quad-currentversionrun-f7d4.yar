rule TTP_XOR_QUAD_CurrentVersionRun_f7d4 {
  strings:
    $key_f7d4 = { a4 bb [2] 80 b5 [2] ab 99 [2] 85 bb [2] 91 a0 [2] 9e ba [2] 80 a7 [2] 82 a6 [2] 99 a0 [2] 85 a7 [2] 99 88 }

  condition:
    any of them
}