rule TTP_XOR_QUAD_CurrentVersionRun_70d4 {
  strings:
    $key_70d4 = { 23 bb [2] 07 b5 [2] 2c 99 [2] 02 bb [2] 16 a0 [2] 19 ba [2] 07 a7 [2] 05 a6 [2] 1e a0 [2] 02 a7 [2] 1e 88 }

  condition:
    any of them
}