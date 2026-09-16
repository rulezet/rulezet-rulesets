rule TTP_XOR_MULT_DOSStub_8607 {
  strings:
    $key_8607 = { d2 6f [2] a6 77 [2] e1 75 [2] a6 64 [2] e8 68 [2] e4 62 [2] f3 69 [2] e8 27 [2] d5 }

  condition:
    any of them
}