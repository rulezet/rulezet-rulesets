rule TTP_XOR_MULT_DOSStub_8684 {
  strings:
    $key_8684 = { d2 ec [2] a6 f4 [2] e1 f6 [2] a6 e7 [2] e8 eb [2] e4 e1 [2] f3 ea [2] e8 a4 [2] d5 }

  condition:
    any of them
}