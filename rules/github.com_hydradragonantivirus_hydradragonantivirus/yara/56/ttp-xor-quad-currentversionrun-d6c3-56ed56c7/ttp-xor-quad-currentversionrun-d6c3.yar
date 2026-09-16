rule TTP_XOR_QUAD_CurrentVersionRun_d6c3 {
  strings:
    $key_d6c3 = { 85 ac [2] a1 a2 [2] 8a 8e [2] a4 ac [2] b0 b7 [2] bf ad [2] a1 b0 [2] a3 b1 [2] b8 b7 [2] a4 b0 [2] b8 9f }

  condition:
    any of them
}