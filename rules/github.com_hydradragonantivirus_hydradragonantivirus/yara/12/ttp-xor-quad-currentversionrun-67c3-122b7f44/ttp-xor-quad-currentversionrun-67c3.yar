rule TTP_XOR_QUAD_CurrentVersionRun_67c3 {
  strings:
    $key_67c3 = { 34 ac [2] 10 a2 [2] 3b 8e [2] 15 ac [2] 01 b7 [2] 0e ad [2] 10 b0 [2] 12 b1 [2] 09 b7 [2] 15 b0 [2] 09 9f }

  condition:
    any of them
}