rule TTP_XOR_QUAD_CurrentVersionRun_d2c4 {
  strings:
    $key_d2c4 = { 81 ab [2] a5 a5 [2] 8e 89 [2] a0 ab [2] b4 b0 [2] bb aa [2] a5 b7 [2] a7 b6 [2] bc b0 [2] a0 b7 [2] bc 98 }

  condition:
    any of them
}