rule TTP_XOR_QUAD_CurrentVersionRun_42d5 {
  strings:
    $key_42d5 = { 11 ba [2] 35 b4 [2] 1e 98 [2] 30 ba [2] 24 a1 [2] 2b bb [2] 35 a6 [2] 37 a7 [2] 2c a1 [2] 30 a6 [2] 2c 89 }

  condition:
    any of them
}