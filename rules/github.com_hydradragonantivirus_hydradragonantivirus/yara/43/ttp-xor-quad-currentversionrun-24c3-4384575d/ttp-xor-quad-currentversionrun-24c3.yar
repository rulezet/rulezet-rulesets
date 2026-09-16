rule TTP_XOR_QUAD_CurrentVersionRun_24c3 {
  strings:
    $key_24c3 = { 77 ac [2] 53 a2 [2] 78 8e [2] 56 ac [2] 42 b7 [2] 4d ad [2] 53 b0 [2] 51 b1 [2] 4a b7 [2] 56 b0 [2] 4a 9f }

  condition:
    any of them
}