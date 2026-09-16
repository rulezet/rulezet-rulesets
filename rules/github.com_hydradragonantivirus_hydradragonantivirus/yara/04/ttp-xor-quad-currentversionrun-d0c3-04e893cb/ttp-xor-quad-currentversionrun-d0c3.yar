rule TTP_XOR_QUAD_CurrentVersionRun_d0c3 {
  strings:
    $key_d0c3 = { 83 ac [2] a7 a2 [2] 8c 8e [2] a2 ac [2] b6 b7 [2] b9 ad [2] a7 b0 [2] a5 b1 [2] be b7 [2] a2 b0 [2] be 9f }

  condition:
    any of them
}