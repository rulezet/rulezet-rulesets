rule TTP_XOR_QUAD_CurrentVersionRun_f4c3 {
  strings:
    $key_f4c3 = { a7 ac [2] 83 a2 [2] a8 8e [2] 86 ac [2] 92 b7 [2] 9d ad [2] 83 b0 [2] 81 b1 [2] 9a b7 [2] 86 b0 [2] 9a 9f }

  condition:
    any of them
}