rule TTP_XOR_MULT_DOSStub_c6b1 {
  strings:
    $key_c6b1 = { 92 d9 [2] e6 c1 [2] a1 c3 [2] e6 d2 [2] a8 de [2] a4 d4 [2] b3 df [2] a8 91 [2] 95 }

  condition:
    any of them
}