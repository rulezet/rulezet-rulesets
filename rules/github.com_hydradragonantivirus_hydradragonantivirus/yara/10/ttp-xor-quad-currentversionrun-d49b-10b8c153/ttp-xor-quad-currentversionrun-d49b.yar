rule TTP_XOR_QUAD_CurrentVersionRun_d49b {
  strings:
    $key_d49b = { 87 f4 [2] a3 fa [2] 88 d6 [2] a6 f4 [2] b2 ef [2] bd f5 [2] a3 e8 [2] a1 e9 [2] ba ef [2] a6 e8 [2] ba c7 }

  condition:
    any of them
}