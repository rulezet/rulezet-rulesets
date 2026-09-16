rule TTP_XOR_QUAD_CurrentVersionRun_ca85 {
  strings:
    $key_ca85 = { 99 ea [2] bd e4 [2] 96 c8 [2] b8 ea [2] ac f1 [2] a3 eb [2] bd f6 [2] bf f7 [2] a4 f1 [2] b8 f6 [2] a4 d9 }

  condition:
    any of them
}