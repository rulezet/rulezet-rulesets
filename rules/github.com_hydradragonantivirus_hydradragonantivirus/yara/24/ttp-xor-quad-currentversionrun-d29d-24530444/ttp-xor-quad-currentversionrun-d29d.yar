rule TTP_XOR_QUAD_CurrentVersionRun_d29d {
  strings:
    $key_d29d = { 81 f2 [2] a5 fc [2] 8e d0 [2] a0 f2 [2] b4 e9 [2] bb f3 [2] a5 ee [2] a7 ef [2] bc e9 [2] a0 ee [2] bc c1 }

  condition:
    any of them
}