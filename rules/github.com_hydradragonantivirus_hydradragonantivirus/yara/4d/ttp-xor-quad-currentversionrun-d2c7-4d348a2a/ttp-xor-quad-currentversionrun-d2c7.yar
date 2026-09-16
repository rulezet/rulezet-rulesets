rule TTP_XOR_QUAD_CurrentVersionRun_d2c7 {
  strings:
    $key_d2c7 = { 81 a8 [2] a5 a6 [2] 8e 8a [2] a0 a8 [2] b4 b3 [2] bb a9 [2] a5 b4 [2] a7 b5 [2] bc b3 [2] a0 b4 [2] bc 9b }

  condition:
    any of them
}