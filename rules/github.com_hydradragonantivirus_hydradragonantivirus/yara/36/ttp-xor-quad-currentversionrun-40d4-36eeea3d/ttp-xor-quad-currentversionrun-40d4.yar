rule TTP_XOR_QUAD_CurrentVersionRun_40d4 {
  strings:
    $key_40d4 = { 13 bb [2] 37 b5 [2] 1c 99 [2] 32 bb [2] 26 a0 [2] 29 ba [2] 37 a7 [2] 35 a6 [2] 2e a0 [2] 32 a7 [2] 2e 88 }

  condition:
    any of them
}