rule TTP_XOR_QUAD_CurrentVersionRun_70c9 {
  strings:
    $key_70c9 = { 23 a6 [2] 07 a8 [2] 2c 84 [2] 02 a6 [2] 16 bd [2] 19 a7 [2] 07 ba [2] 05 bb [2] 1e bd [2] 02 ba [2] 1e 95 }

  condition:
    any of them
}