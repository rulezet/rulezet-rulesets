rule TTP_XOR_MULT_DOSStub_8646 {
  strings:
    $key_8646 = { d2 2e [2] a6 36 [2] e1 34 [2] a6 25 [2] e8 29 [2] e4 23 [2] f3 28 [2] e8 66 [2] d5 }

  condition:
    any of them
}