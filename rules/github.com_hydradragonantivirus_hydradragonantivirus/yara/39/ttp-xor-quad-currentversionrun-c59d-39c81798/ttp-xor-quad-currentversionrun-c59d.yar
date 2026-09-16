rule TTP_XOR_QUAD_CurrentVersionRun_c59d {
  strings:
    $key_c59d = { 96 f2 [2] b2 fc [2] 99 d0 [2] b7 f2 [2] a3 e9 [2] ac f3 [2] b2 ee [2] b0 ef [2] ab e9 [2] b7 ee [2] ab c1 }

  condition:
    any of them
}