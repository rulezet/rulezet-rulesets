rule TTP_XOR_QUAD_CurrentVersionRun_5ec8 {
  strings:
    $key_5ec8 = { 0d a7 [2] 29 a9 [2] 02 85 [2] 2c a7 [2] 38 bc [2] 37 a6 [2] 29 bb [2] 2b ba [2] 30 bc [2] 2c bb [2] 30 94 }

  condition:
    any of them
}