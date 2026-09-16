rule TTP_XOR_QUAD_CurrentVersionRun_5ed5 {
  strings:
    $key_5ed5 = { 0d ba [2] 29 b4 [2] 02 98 [2] 2c ba [2] 38 a1 [2] 37 bb [2] 29 a6 [2] 2b a7 [2] 30 a1 [2] 2c a6 [2] 30 89 }

  condition:
    any of them
}