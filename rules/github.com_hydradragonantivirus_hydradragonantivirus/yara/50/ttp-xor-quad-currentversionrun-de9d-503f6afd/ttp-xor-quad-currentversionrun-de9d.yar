rule TTP_XOR_QUAD_CurrentVersionRun_de9d {
  strings:
    $key_de9d = { 8d f2 [2] a9 fc [2] 82 d0 [2] ac f2 [2] b8 e9 [2] b7 f3 [2] a9 ee [2] ab ef [2] b0 e9 [2] ac ee [2] b0 c1 }

  condition:
    any of them
}