rule TTP_XOR_QUAD_CurrentVersionRun_d7c3 {
  strings:
    $key_d7c3 = { 84 ac [2] a0 a2 [2] 8b 8e [2] a5 ac [2] b1 b7 [2] be ad [2] a0 b0 [2] a2 b1 [2] b9 b7 [2] a5 b0 [2] b9 9f }

  condition:
    any of them
}