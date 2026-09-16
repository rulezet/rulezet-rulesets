rule TTP_XOR_QUAD_CurrentVersionRun_25c3 {
  strings:
    $key_25c3 = { 76 ac [2] 52 a2 [2] 79 8e [2] 57 ac [2] 43 b7 [2] 4c ad [2] 52 b0 [2] 50 b1 [2] 4b b7 [2] 57 b0 [2] 4b 9f }

  condition:
    any of them
}