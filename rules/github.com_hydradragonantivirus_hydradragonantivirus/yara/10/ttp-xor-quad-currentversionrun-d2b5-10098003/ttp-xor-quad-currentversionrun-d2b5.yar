rule TTP_XOR_QUAD_CurrentVersionRun_d2b5 {
  strings:
    $key_d2b5 = { 81 da [2] a5 d4 [2] 8e f8 [2] a0 da [2] b4 c1 [2] bb db [2] a5 c6 [2] a7 c7 [2] bc c1 [2] a0 c6 [2] bc e9 }

  condition:
    any of them
}