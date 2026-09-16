rule TTP_XOR_QUAD_CurrentVersionRun_d384 {
  strings:
    $key_d384 = { 80 eb [2] a4 e5 [2] 8f c9 [2] a1 eb [2] b5 f0 [2] ba ea [2] a4 f7 [2] a6 f6 [2] bd f0 [2] a1 f7 [2] bd d8 }

  condition:
    any of them
}