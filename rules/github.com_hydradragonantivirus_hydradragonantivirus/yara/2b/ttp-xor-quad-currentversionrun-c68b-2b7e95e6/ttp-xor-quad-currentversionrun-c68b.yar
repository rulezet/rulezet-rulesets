rule TTP_XOR_QUAD_CurrentVersionRun_c68b {
  strings:
    $key_c68b = { 95 e4 [2] b1 ea [2] 9a c6 [2] b4 e4 [2] a0 ff [2] af e5 [2] b1 f8 [2] b3 f9 [2] a8 ff [2] b4 f8 [2] a8 d7 }

  condition:
    any of them
}