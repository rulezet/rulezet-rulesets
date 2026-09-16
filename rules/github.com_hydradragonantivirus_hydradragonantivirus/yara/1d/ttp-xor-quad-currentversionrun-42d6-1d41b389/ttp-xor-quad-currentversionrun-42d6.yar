rule TTP_XOR_QUAD_CurrentVersionRun_42d6 {
  strings:
    $key_42d6 = { 11 b9 [2] 35 b7 [2] 1e 9b [2] 30 b9 [2] 24 a2 [2] 2b b8 [2] 35 a5 [2] 37 a4 [2] 2c a2 [2] 30 a5 [2] 2c 8a }

  condition:
    any of them
}