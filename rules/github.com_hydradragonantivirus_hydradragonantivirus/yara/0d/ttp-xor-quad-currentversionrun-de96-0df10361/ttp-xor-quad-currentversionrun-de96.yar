rule TTP_XOR_QUAD_CurrentVersionRun_de96 {
  strings:
    $key_de96 = { 8d f9 [2] a9 f7 [2] 82 db [2] ac f9 [2] b8 e2 [2] b7 f8 [2] a9 e5 [2] ab e4 [2] b0 e2 [2] ac e5 [2] b0 ca }

  condition:
    any of them
}