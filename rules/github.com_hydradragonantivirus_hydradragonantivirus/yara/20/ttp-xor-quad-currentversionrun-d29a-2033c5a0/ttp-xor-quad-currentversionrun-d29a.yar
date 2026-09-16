rule TTP_XOR_QUAD_CurrentVersionRun_d29a {
  strings:
    $key_d29a = { 81 f5 [2] a5 fb [2] 8e d7 [2] a0 f5 [2] b4 ee [2] bb f4 [2] a5 e9 [2] a7 e8 [2] bc ee [2] a0 e9 [2] bc c6 }

  condition:
    any of them
}