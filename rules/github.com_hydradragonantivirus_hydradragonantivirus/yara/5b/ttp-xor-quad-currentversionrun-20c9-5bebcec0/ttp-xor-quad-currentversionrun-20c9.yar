rule TTP_XOR_QUAD_CurrentVersionRun_20c9 {
  strings:
    $key_20c9 = { 73 a6 [2] 57 a8 [2] 7c 84 [2] 52 a6 [2] 46 bd [2] 49 a7 [2] 57 ba [2] 55 bb [2] 4e bd [2] 52 ba [2] 4e 95 }

  condition:
    any of them
}