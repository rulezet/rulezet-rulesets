rule TTP_XOR_QUAD_CurrentVersionRun_c19d {
  strings:
    $key_c19d = { 92 f2 [2] b6 fc [2] 9d d0 [2] b3 f2 [2] a7 e9 [2] a8 f3 [2] b6 ee [2] b4 ef [2] af e9 [2] b3 ee [2] af c1 }

  condition:
    any of them
}