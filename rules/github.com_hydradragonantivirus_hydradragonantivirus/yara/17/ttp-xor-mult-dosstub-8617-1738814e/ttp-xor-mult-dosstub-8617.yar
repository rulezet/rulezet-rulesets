rule TTP_XOR_MULT_DOSStub_8617 {
  strings:
    $key_8617 = { d2 7f [2] a6 67 [2] e1 65 [2] a6 74 [2] e8 78 [2] e4 72 [2] f3 79 [2] e8 37 [2] d5 }

  condition:
    any of them
}