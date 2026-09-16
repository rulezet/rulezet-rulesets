rule TTP_XOR_QUAD_CurrentVersionRun_d2d6 {
  strings:
    $key_d2d6 = { 81 b9 [2] a5 b7 [2] 8e 9b [2] a0 b9 [2] b4 a2 [2] bb b8 [2] a5 a5 [2] a7 a4 [2] bc a2 [2] a0 a5 [2] bc 8a }

  condition:
    any of them
}