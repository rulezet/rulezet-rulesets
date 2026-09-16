rule TTP_XOR_QUAD_CurrentVersionRun_ca8b {
  strings:
    $key_ca8b = { 99 e4 [2] bd ea [2] 96 c6 [2] b8 e4 [2] ac ff [2] a3 e5 [2] bd f8 [2] bf f9 [2] a4 ff [2] b8 f8 [2] a4 d7 }

  condition:
    any of them
}