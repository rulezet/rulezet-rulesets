rule TTP_XOR_QUAD_CurrentVersionRun_d2c3 {
  strings:
    $key_d2c3 = { 81 ac [2] a5 a2 [2] 8e 8e [2] a0 ac [2] b4 b7 [2] bb ad [2] a5 b0 [2] a7 b1 [2] bc b7 [2] a0 b0 [2] bc 9f }

  condition:
    any of them
}