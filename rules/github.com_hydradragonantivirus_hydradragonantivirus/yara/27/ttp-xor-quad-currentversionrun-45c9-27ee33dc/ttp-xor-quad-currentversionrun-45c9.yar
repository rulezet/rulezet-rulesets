rule TTP_XOR_QUAD_CurrentVersionRun_45c9 {
  strings:
    $key_45c9 = { 16 a6 [2] 32 a8 [2] 19 84 [2] 37 a6 [2] 23 bd [2] 2c a7 [2] 32 ba [2] 30 bb [2] 2b bd [2] 37 ba [2] 2b 95 }

  condition:
    any of them
}