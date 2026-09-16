rule TTP_XOR_QUAD_CurrentVersionRun_36c3 {
  strings:
    $key_36c3 = { 65 ac [2] 41 a2 [2] 6a 8e [2] 44 ac [2] 50 b7 [2] 5f ad [2] 41 b0 [2] 43 b1 [2] 58 b7 [2] 44 b0 [2] 58 9f }

  condition:
    any of them
}