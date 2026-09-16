rule TTP_XOR_QUAD_CurrentVersionRun_d294 {
  strings:
    $key_d294 = { 81 fb [2] a5 f5 [2] 8e d9 [2] a0 fb [2] b4 e0 [2] bb fa [2] a5 e7 [2] a7 e6 [2] bc e0 [2] a0 e7 [2] bc c8 }

  condition:
    any of them
}