rule TTP_XOR_MULT_DOSStub_8609 {
  strings:
    $key_8609 = { d2 61 [2] a6 79 [2] e1 7b [2] a6 6a [2] e8 66 [2] e4 6c [2] f3 67 [2] e8 29 [2] d5 }

  condition:
    any of them
}