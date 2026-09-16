rule TTP_XOR_QUAD_CurrentVersionRun_de9b {
  strings:
    $key_de9b = { 8d f4 [2] a9 fa [2] 82 d6 [2] ac f4 [2] b8 ef [2] b7 f5 [2] a9 e8 [2] ab e9 [2] b0 ef [2] ac e8 [2] b0 c7 }

  condition:
    any of them
}