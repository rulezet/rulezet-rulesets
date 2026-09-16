rule TTP_XOR_QUAD_CurrentVersionRun_d29b {
  strings:
    $key_d29b = { 81 f4 [2] a5 fa [2] 8e d6 [2] a0 f4 [2] b4 ef [2] bb f5 [2] a5 e8 [2] a7 e9 [2] bc ef [2] a0 e8 [2] bc c7 }

  condition:
    any of them
}