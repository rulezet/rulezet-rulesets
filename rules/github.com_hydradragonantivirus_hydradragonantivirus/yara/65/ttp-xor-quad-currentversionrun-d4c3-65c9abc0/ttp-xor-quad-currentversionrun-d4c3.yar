rule TTP_XOR_QUAD_CurrentVersionRun_d4c3 {
  strings:
    $key_d4c3 = { 87 ac [2] a3 a2 [2] 88 8e [2] a6 ac [2] b2 b7 [2] bd ad [2] a3 b0 [2] a1 b1 [2] ba b7 [2] a6 b0 [2] ba 9f }

  condition:
    any of them
}