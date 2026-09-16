rule TTP_XOR_MULT_DOSStub_8663 {
  strings:
    $key_8663 = { d2 0b [2] a6 13 [2] e1 11 [2] a6 00 [2] e8 0c [2] e4 06 [2] f3 0d [2] e8 43 [2] d5 }

  condition:
    any of them
}