rule TTP_XOR_QUAD_CurrentVersionRun_d1c3 {
  strings:
    $key_d1c3 = { 82 ac [2] a6 a2 [2] 8d 8e [2] a3 ac [2] b7 b7 [2] b8 ad [2] a6 b0 [2] a4 b1 [2] bf b7 [2] a3 b0 [2] bf 9f }

  condition:
    any of them
}