rule TTP_XOR_MULT_DOSStub_8105 {
  strings:
    $key_8105 = { d5 6d [2] a1 75 [2] e6 77 [2] a1 66 [2] ef 6a [2] e3 60 [2] f4 6b [2] ef 25 [2] d2 }

  condition:
    any of them
}