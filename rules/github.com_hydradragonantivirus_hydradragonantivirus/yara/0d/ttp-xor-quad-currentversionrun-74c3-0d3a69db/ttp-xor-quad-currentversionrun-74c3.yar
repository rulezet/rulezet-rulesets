rule TTP_XOR_QUAD_CurrentVersionRun_74c3 {
  strings:
    $key_74c3 = { 27 ac [2] 03 a2 [2] 28 8e [2] 06 ac [2] 12 b7 [2] 1d ad [2] 03 b0 [2] 01 b1 [2] 1a b7 [2] 06 b0 [2] 1a 9f }

  condition:
    any of them
}