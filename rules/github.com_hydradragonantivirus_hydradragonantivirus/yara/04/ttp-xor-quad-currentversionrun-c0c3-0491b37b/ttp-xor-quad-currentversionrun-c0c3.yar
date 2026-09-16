rule TTP_XOR_QUAD_CurrentVersionRun_c0c3 {
  strings:
    $key_c0c3 = { 93 ac [2] b7 a2 [2] 9c 8e [2] b2 ac [2] a6 b7 [2] a9 ad [2] b7 b0 [2] b5 b1 [2] ae b7 [2] b2 b0 [2] ae 9f }

  condition:
    any of them
}