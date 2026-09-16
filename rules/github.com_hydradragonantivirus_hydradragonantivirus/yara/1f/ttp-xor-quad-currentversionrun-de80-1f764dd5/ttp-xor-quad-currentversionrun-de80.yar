rule TTP_XOR_QUAD_CurrentVersionRun_de80 {
  strings:
    $key_de80 = { 8d ef [2] a9 e1 [2] 82 cd [2] ac ef [2] b8 f4 [2] b7 ee [2] a9 f3 [2] ab f2 [2] b0 f4 [2] ac f3 [2] b0 dc }

  condition:
    any of them
}