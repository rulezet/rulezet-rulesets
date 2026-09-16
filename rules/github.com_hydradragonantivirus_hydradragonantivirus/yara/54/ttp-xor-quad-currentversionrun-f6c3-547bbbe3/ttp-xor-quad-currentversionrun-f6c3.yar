rule TTP_XOR_QUAD_CurrentVersionRun_f6c3 {
  strings:
    $key_f6c3 = { a5 ac [2] 81 a2 [2] aa 8e [2] 84 ac [2] 90 b7 [2] 9f ad [2] 81 b0 [2] 83 b1 [2] 98 b7 [2] 84 b0 [2] 98 9f }

  condition:
    any of them
}