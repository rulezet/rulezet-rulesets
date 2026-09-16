rule TTP_XOR_MULT_DOSStub_8640 {
  strings:
    $key_8640 = { d2 28 [2] a6 30 [2] e1 32 [2] a6 23 [2] e8 2f [2] e4 25 [2] f3 2e [2] e8 60 [2] d5 }

  condition:
    any of them
}