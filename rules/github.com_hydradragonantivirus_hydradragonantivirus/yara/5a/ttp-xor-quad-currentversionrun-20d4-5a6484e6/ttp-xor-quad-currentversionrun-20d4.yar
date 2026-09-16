rule TTP_XOR_QUAD_CurrentVersionRun_20d4 {
  strings:
    $key_20d4 = { 73 bb [2] 57 b5 [2] 7c 99 [2] 52 bb [2] 46 a0 [2] 49 ba [2] 57 a7 [2] 55 a6 [2] 4e a0 [2] 52 a7 [2] 4e 88 }

  condition:
    any of them
}