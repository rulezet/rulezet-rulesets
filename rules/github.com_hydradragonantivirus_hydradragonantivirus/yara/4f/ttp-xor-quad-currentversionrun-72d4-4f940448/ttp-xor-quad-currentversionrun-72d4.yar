rule TTP_XOR_QUAD_CurrentVersionRun_72d4 {
  strings:
    $key_72d4 = { 21 bb [2] 05 b5 [2] 2e 99 [2] 00 bb [2] 14 a0 [2] 1b ba [2] 05 a7 [2] 07 a6 [2] 1c a0 [2] 00 a7 [2] 1c 88 }

  condition:
    any of them
}