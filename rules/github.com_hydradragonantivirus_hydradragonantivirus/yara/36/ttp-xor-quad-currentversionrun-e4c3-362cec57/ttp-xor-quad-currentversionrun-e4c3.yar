rule TTP_XOR_QUAD_CurrentVersionRun_e4c3 {
  strings:
    $key_e4c3 = { b7 ac [2] 93 a2 [2] b8 8e [2] 96 ac [2] 82 b7 [2] 8d ad [2] 93 b0 [2] 91 b1 [2] 8a b7 [2] 96 b0 [2] 8a 9f }

  condition:
    any of them
}