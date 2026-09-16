rule TTP_XOR_MULT_DOSStub_8783 {
  strings:
    $key_8783 = { d3 eb [2] a7 f3 [2] e0 f1 [2] a7 e0 [2] e9 ec [2] e5 e6 [2] f2 ed [2] e9 a3 [2] d4 }

  condition:
    any of them
}