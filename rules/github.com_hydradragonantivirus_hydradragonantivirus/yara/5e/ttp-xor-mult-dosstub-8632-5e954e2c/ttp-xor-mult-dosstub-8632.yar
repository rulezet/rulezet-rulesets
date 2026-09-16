rule TTP_XOR_MULT_DOSStub_8632 {
  strings:
    $key_8632 = { d2 5a [2] a6 42 [2] e1 40 [2] a6 51 [2] e8 5d [2] e4 57 [2] f3 5c [2] e8 12 [2] d5 }

  condition:
    any of them
}