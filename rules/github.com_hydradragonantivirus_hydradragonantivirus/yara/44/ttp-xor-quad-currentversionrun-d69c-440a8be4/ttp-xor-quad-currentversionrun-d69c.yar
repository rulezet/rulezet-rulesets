rule TTP_XOR_QUAD_CurrentVersionRun_d69c {
  strings:
    $key_d69c = { 85 f3 [2] a1 fd [2] 8a d1 [2] a4 f3 [2] b0 e8 [2] bf f2 [2] a1 ef [2] a3 ee [2] b8 e8 [2] a4 ef [2] b8 c0 }

  condition:
    any of them
}