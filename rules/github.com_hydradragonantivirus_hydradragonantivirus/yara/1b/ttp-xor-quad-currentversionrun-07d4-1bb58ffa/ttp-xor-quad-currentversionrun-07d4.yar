rule TTP_XOR_QUAD_CurrentVersionRun_07d4 {
  strings:
    $key_07d4 = { 54 bb [2] 70 b5 [2] 5b 99 [2] 75 bb [2] 61 a0 [2] 6e ba [2] 70 a7 [2] 72 a6 [2] 69 a0 [2] 75 a7 [2] 69 88 }

  condition:
    any of them
}