rule TTP_XOR_MULT_DOSStub_8691 {
  strings:
    $key_8691 = { d2 f9 [2] a6 e1 [2] e1 e3 [2] a6 f2 [2] e8 fe [2] e4 f4 [2] f3 ff [2] e8 b1 [2] d5 }

  condition:
    any of them
}