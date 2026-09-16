rule TTP_XOR_QUAD_CurrentVersionRun_c69d {
  strings:
    $key_c69d = { 95 f2 [2] b1 fc [2] 9a d0 [2] b4 f2 [2] a0 e9 [2] af f3 [2] b1 ee [2] b3 ef [2] a8 e9 [2] b4 ee [2] a8 c1 }

  condition:
    any of them
}