rule TTP_XOR_QUAD_CurrentVersionRun_70d5 {
  strings:
    $key_70d5 = { 23 ba [2] 07 b4 [2] 2c 98 [2] 02 ba [2] 16 a1 [2] 19 bb [2] 07 a6 [2] 05 a7 [2] 1e a1 [2] 02 a6 [2] 1e 89 }

  condition:
    any of them
}