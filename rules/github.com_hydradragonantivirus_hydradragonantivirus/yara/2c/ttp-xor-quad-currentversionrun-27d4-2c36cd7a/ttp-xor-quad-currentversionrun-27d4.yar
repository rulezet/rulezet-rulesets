rule TTP_XOR_QUAD_CurrentVersionRun_27d4 {
  strings:
    $key_27d4 = { 74 bb [2] 50 b5 [2] 7b 99 [2] 55 bb [2] 41 a0 [2] 4e ba [2] 50 a7 [2] 52 a6 [2] 49 a0 [2] 55 a7 [2] 49 88 }

  condition:
    any of them
}