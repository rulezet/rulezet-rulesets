rule TTP_XOR_QUAD_CurrentVersionRun_c4c3 {
  strings:
    $key_c4c3 = { 97 ac [2] b3 a2 [2] 98 8e [2] b6 ac [2] a2 b7 [2] ad ad [2] b3 b0 [2] b1 b1 [2] aa b7 [2] b6 b0 [2] aa 9f }

  condition:
    any of them
}