rule TTP_XOR_QUAD_CurrentVersionRun_d2b4 {
  strings:
    $key_d2b4 = { 81 db [2] a5 d5 [2] 8e f9 [2] a0 db [2] b4 c0 [2] bb da [2] a5 c7 [2] a7 c6 [2] bc c0 [2] a0 c7 [2] bc e8 }

  condition:
    any of them
}