rule TTP_XOR_MULT_DOSStub_c685 {
  strings:
    $key_c685 = { 92 ed [2] e6 f5 [2] a1 f7 [2] e6 e6 [2] a8 ea [2] a4 e0 [2] b3 eb [2] a8 a5 [2] 95 }

  condition:
    any of them
}