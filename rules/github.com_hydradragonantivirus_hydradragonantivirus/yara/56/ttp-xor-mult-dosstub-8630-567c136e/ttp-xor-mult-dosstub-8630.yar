rule TTP_XOR_MULT_DOSStub_8630 {
  strings:
    $key_8630 = { d2 58 [2] a6 40 [2] e1 42 [2] a6 53 [2] e8 5f [2] e4 55 [2] f3 5e [2] e8 10 [2] d5 }

  condition:
    any of them
}