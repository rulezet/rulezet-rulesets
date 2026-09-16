rule TTP_XOR_QUAD_CurrentVersionRun_d5c3 {
  strings:
    $key_d5c3 = { 86 ac [2] a2 a2 [2] 89 8e [2] a7 ac [2] b3 b7 [2] bc ad [2] a2 b0 [2] a0 b1 [2] bb b7 [2] a7 b0 [2] bb 9f }

  condition:
    any of them
}