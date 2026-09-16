rule TTP_XOR_MULT_DOSStub_8602 {
  strings:
    $key_8602 = { d2 6a [2] a6 72 [2] e1 70 [2] a6 61 [2] e8 6d [2] e4 67 [2] f3 6c [2] e8 22 [2] d5 }

  condition:
    any of them
}