rule TTP_XOR_QUAD_CurrentVersionRun_c59c {
  strings:
    $key_c59c = { 96 f3 [2] b2 fd [2] 99 d1 [2] b7 f3 [2] a3 e8 [2] ac f2 [2] b2 ef [2] b0 ee [2] ab e8 [2] b7 ef [2] ab c0 }

  condition:
    any of them
}