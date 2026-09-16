rule TTP_XOR_QUAD_CurrentVersionRun_c6c3 {
  strings:
    $key_c6c3 = { 95 ac [2] b1 a2 [2] 9a 8e [2] b4 ac [2] a0 b7 [2] af ad [2] b1 b0 [2] b3 b1 [2] a8 b7 [2] b4 b0 [2] a8 9f }

  condition:
    any of them
}