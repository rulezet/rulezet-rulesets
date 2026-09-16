rule TTP_XOR_MULT_DOSStub_8614 {
  strings:
    $key_8614 = { d2 7c [2] a6 64 [2] e1 66 [2] a6 77 [2] e8 7b [2] e4 71 [2] f3 7a [2] e8 34 [2] d5 }

  condition:
    any of them
}