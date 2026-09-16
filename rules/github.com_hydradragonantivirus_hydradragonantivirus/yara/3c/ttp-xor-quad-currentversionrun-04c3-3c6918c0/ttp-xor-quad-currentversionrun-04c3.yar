rule TTP_XOR_QUAD_CurrentVersionRun_04c3 {
  strings:
    $key_04c3 = { 57 ac [2] 73 a2 [2] 58 8e [2] 76 ac [2] 62 b7 [2] 6d ad [2] 73 b0 [2] 71 b1 [2] 6a b7 [2] 76 b0 [2] 6a 9f }

  condition:
    any of them
}