rule TTP_XOR_QUAD_CurrentVersionRun_77d4 {
  strings:
    $key_77d4 = { 24 bb [2] 00 b5 [2] 2b 99 [2] 05 bb [2] 11 a0 [2] 1e ba [2] 00 a7 [2] 02 a6 [2] 19 a0 [2] 05 a7 [2] 19 88 }

  condition:
    any of them
}