rule TTP_XOR_QUAD_CurrentVersionRun_22c3 {
  strings:
    $key_22c3 = { 71 ac [2] 55 a2 [2] 7e 8e [2] 50 ac [2] 44 b7 [2] 4b ad [2] 55 b0 [2] 57 b1 [2] 4c b7 [2] 50 b0 [2] 4c 9f }

  condition:
    any of them
}