rule TTP_XOR_MULT_DOSStub_a7b1 {
  strings:
    $key_a7b1 = { f3 d9 [2] 87 c1 [2] c0 c3 [2] 87 d2 [2] c9 de [2] c5 d4 [2] d2 df [2] c9 91 [2] f4 }

  condition:
    any of them
}