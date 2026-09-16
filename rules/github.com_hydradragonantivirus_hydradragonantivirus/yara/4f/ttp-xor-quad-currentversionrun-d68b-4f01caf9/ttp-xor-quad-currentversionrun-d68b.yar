rule TTP_XOR_QUAD_CurrentVersionRun_d68b {
  strings:
    $key_d68b = { 85 e4 [2] a1 ea [2] 8a c6 [2] a4 e4 [2] b0 ff [2] bf e5 [2] a1 f8 [2] a3 f9 [2] b8 ff [2] a4 f8 [2] b8 d7 }

  condition:
    any of them
}