rule TTP_XOR_QUAD_CurrentVersionRun_75d4 {
  strings:
    $key_75d4 = { 26 bb [2] 02 b5 [2] 29 99 [2] 07 bb [2] 13 a0 [2] 1c ba [2] 02 a7 [2] 00 a6 [2] 1b a0 [2] 07 a7 [2] 1b 88 }

  condition:
    any of them
}