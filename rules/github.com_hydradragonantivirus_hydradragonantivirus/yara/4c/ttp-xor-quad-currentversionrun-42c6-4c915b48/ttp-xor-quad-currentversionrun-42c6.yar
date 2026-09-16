rule TTP_XOR_QUAD_CurrentVersionRun_42c6 {
  strings:
    $key_42c6 = { 11 a9 [2] 35 a7 [2] 1e 8b [2] 30 a9 [2] 24 b2 [2] 2b a8 [2] 35 b5 [2] 37 b4 [2] 2c b2 [2] 30 b5 [2] 2c 9a }

  condition:
    any of them
}