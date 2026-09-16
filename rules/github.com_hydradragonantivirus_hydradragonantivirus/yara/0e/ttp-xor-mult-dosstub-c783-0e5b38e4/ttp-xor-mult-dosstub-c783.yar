rule TTP_XOR_MULT_DOSStub_c783 {
  strings:
    $key_c783 = { 93 eb [2] e7 f3 [2] a0 f1 [2] e7 e0 [2] a9 ec [2] a5 e6 [2] b2 ed [2] a9 a3 [2] 94 }

  condition:
    any of them
}