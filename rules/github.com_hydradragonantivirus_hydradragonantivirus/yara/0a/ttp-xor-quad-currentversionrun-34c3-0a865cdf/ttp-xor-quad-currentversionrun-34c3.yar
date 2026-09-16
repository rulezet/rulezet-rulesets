rule TTP_XOR_QUAD_CurrentVersionRun_34c3 {
  strings:
    $key_34c3 = { 67 ac [2] 43 a2 [2] 68 8e [2] 46 ac [2] 52 b7 [2] 5d ad [2] 43 b0 [2] 41 b1 [2] 5a b7 [2] 46 b0 [2] 5a 9f }

  condition:
    any of them
}