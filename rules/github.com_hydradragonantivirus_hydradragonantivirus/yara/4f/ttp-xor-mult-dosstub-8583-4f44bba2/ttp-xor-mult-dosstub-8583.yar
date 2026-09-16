rule TTP_XOR_MULT_DOSStub_8583 {
  strings:
    $key_8583 = { d1 eb [2] a5 f3 [2] e2 f1 [2] a5 e0 [2] eb ec [2] e7 e6 [2] f0 ed [2] eb a3 [2] d6 }

  condition:
    any of them
}