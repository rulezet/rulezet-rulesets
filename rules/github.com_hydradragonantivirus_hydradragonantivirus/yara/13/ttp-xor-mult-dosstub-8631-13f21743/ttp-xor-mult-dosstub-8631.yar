rule TTP_XOR_MULT_DOSStub_8631 {
  strings:
    $key_8631 = { d2 59 [2] a6 41 [2] e1 43 [2] a6 52 [2] e8 5e [2] e4 54 [2] f3 5f [2] e8 11 [2] d5 }

  condition:
    any of them
}