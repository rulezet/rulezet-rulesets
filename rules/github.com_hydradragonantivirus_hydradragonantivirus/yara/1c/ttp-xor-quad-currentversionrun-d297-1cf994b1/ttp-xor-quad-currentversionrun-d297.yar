rule TTP_XOR_QUAD_CurrentVersionRun_d297 {
  strings:
    $key_d297 = { 81 f8 [2] a5 f6 [2] 8e da [2] a0 f8 [2] b4 e3 [2] bb f9 [2] a5 e4 [2] a7 e5 [2] bc e3 [2] a0 e4 [2] bc cb }

  condition:
    any of them
}