rule TTP_XOR_QUAD_CurrentVersionRun_c29d {
  strings:
    $key_c29d = { 91 f2 [2] b5 fc [2] 9e d0 [2] b0 f2 [2] a4 e9 [2] ab f3 [2] b5 ee [2] b7 ef [2] ac e9 [2] b0 ee [2] ac c1 }

  condition:
    any of them
}