rule TTP_XOR_QUAD_CurrentVersionRun_42c3 {
  strings:
    $key_42c3 = { 11 ac [2] 35 a2 [2] 1e 8e [2] 30 ac [2] 24 b7 [2] 2b ad [2] 35 b0 [2] 37 b1 [2] 2c b7 [2] 30 b0 [2] 2c 9f }

  condition:
    any of them
}