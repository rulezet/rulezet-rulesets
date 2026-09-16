rule TTP_XOR_QUAD_CurrentVersionRun_c29b {
  strings:
    $key_c29b = { 91 f4 [2] b5 fa [2] 9e d6 [2] b0 f4 [2] a4 ef [2] ab f5 [2] b5 e8 [2] b7 e9 [2] ac ef [2] b0 e8 [2] ac c7 }

  condition:
    any of them
}