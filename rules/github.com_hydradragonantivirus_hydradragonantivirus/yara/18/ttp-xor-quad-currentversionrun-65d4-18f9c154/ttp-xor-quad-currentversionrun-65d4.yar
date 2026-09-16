rule TTP_XOR_QUAD_CurrentVersionRun_65d4 {
  strings:
    $key_65d4 = { 36 bb [2] 12 b5 [2] 39 99 [2] 17 bb [2] 03 a0 [2] 0c ba [2] 12 a7 [2] 10 a6 [2] 0b a0 [2] 17 a7 [2] 0b 88 }

  condition:
    any of them
}