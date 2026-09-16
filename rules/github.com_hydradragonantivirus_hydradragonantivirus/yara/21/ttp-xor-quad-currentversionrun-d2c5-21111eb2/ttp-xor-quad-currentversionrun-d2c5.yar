rule TTP_XOR_QUAD_CurrentVersionRun_d2c5 {
  strings:
    $key_d2c5 = { 81 aa [2] a5 a4 [2] 8e 88 [2] a0 aa [2] b4 b1 [2] bb ab [2] a5 b6 [2] a7 b7 [2] bc b1 [2] a0 b6 [2] bc 99 }

  condition:
    any of them
}