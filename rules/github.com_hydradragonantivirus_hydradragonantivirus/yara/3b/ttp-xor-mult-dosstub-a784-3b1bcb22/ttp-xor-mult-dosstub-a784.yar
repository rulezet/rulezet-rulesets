rule TTP_XOR_MULT_DOSStub_a784 {
  strings:
    $key_a784 = { f3 ec [2] 87 f4 [2] c0 f6 [2] 87 e7 [2] c9 eb [2] c5 e1 [2] d2 ea [2] c9 a4 [2] f4 }

  condition:
    any of them
}