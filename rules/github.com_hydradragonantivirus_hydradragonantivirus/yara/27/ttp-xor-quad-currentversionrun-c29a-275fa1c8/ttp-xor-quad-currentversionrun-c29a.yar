rule TTP_XOR_QUAD_CurrentVersionRun_c29a {
  strings:
    $key_c29a = { 91 f5 [2] b5 fb [2] 9e d7 [2] b0 f5 [2] a4 ee [2] ab f4 [2] b5 e9 [2] b7 e8 [2] ac ee [2] b0 e9 [2] ac c6 }

  condition:
    any of them
}