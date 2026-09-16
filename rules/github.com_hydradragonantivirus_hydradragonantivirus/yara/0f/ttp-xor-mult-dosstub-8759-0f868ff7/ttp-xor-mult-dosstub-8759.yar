rule TTP_XOR_MULT_DOSStub_8759 {
  strings:
    $key_8759 = { d3 31 [2] a7 29 [2] e0 2b [2] a7 3a [2] e9 36 [2] e5 3c [2] f2 37 [2] e9 79 [2] d4 }

  condition:
    any of them
}