rule TTP_XOR_QUAD_CurrentVersionRun_52d4 {
  strings:
    $key_52d4 = { 01 bb [2] 25 b5 [2] 0e 99 [2] 20 bb [2] 34 a0 [2] 3b ba [2] 25 a7 [2] 27 a6 [2] 3c a0 [2] 20 a7 [2] 3c 88 }

  condition:
    any of them
}