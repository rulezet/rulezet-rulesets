rule TTP_XOR_QUAD_CurrentVersionRun_47d4 {
  strings:
    $key_47d4 = { 14 bb [2] 30 b5 [2] 1b 99 [2] 35 bb [2] 21 a0 [2] 2e ba [2] 30 a7 [2] 32 a6 [2] 29 a0 [2] 35 a7 [2] 29 88 }

  condition:
    any of them
}