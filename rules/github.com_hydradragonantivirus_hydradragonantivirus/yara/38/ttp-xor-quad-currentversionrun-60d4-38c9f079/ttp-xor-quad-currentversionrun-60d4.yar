rule TTP_XOR_QUAD_CurrentVersionRun_60d4 {
  strings:
    $key_60d4 = { 33 bb [2] 17 b5 [2] 3c 99 [2] 12 bb [2] 06 a0 [2] 09 ba [2] 17 a7 [2] 15 a6 [2] 0e a0 [2] 12 a7 [2] 0e 88 }

  condition:
    any of them
}