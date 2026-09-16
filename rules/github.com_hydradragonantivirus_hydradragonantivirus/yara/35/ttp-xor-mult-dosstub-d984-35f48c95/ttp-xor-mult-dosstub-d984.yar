rule TTP_XOR_MULT_DOSStub_d984 {
  strings:
    $key_d984 = { 8d ec [2] f9 f4 [2] be f6 [2] f9 e7 [2] b7 eb [2] bb e1 [2] ac ea [2] b7 a4 [2] 8a }

  condition:
    any of them
}