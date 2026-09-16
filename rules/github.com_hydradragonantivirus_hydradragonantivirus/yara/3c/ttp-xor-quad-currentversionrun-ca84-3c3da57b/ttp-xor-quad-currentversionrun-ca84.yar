rule TTP_XOR_QUAD_CurrentVersionRun_ca84 {
  strings:
    $key_ca84 = { 99 eb [2] bd e5 [2] 96 c9 [2] b8 eb [2] ac f0 [2] a3 ea [2] bd f7 [2] bf f6 [2] a4 f0 [2] b8 f7 [2] a4 d8 }

  condition:
    any of them
}