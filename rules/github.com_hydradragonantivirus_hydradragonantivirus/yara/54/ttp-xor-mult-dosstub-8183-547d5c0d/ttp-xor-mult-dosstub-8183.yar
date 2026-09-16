rule TTP_XOR_MULT_DOSStub_8183 {
  strings:
    $key_8183 = { d5 eb [2] a1 f3 [2] e6 f1 [2] a1 e0 [2] ef ec [2] e3 e6 [2] f4 ed [2] ef a3 [2] d2 }

  condition:
    any of them
}