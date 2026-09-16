rule TTP_XOR_QUAD_CurrentVersionRun_d499 {
  strings:
    $key_d499 = { 87 f6 [2] a3 f8 [2] 88 d4 [2] a6 f6 [2] b2 ed [2] bd f7 [2] a3 ea [2] a1 eb [2] ba ed [2] a6 ea [2] ba c5 }

  condition:
    any of them
}