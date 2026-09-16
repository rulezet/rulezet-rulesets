rule TTP_XOR_MULT_DOSStub_86b1 {
  strings:
    $key_86b1 = { d2 d9 [2] a6 c1 [2] e1 c3 [2] a6 d2 [2] e8 de [2] e4 d4 [2] f3 df [2] e8 91 [2] d5 }

  condition:
    any of them
}