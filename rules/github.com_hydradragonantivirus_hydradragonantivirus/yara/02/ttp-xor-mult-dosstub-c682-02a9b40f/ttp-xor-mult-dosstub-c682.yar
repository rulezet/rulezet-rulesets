rule TTP_XOR_MULT_DOSStub_c682 {
  strings:
    $key_c682 = { 92 ea [2] e6 f2 [2] a1 f0 [2] e6 e1 [2] a8 ed [2] a4 e7 [2] b3 ec [2] a8 a2 [2] 95 }

  condition:
    any of them
}