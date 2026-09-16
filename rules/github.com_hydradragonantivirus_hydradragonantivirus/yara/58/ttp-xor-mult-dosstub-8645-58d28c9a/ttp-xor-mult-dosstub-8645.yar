rule TTP_XOR_MULT_DOSStub_8645 {
  strings:
    $key_8645 = { d2 2d [2] a6 35 [2] e1 37 [2] a6 26 [2] e8 2a [2] e4 20 [2] f3 2b [2] e8 65 [2] d5 }

  condition:
    any of them
}