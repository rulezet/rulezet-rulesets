rule TTP_XOR_QUAD_CurrentVersionRun_fb80 {
  strings:
    $key_fb80 = { a8 ef [2] 8c e1 [2] a7 cd [2] 89 ef [2] 9d f4 [2] 92 ee [2] 8c f3 [2] 8e f2 [2] 95 f4 [2] 89 f3 [2] 95 dc }

  condition:
    any of them
}