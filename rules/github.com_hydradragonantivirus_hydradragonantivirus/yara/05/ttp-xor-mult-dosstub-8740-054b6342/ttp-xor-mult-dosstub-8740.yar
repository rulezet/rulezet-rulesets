rule TTP_XOR_MULT_DOSStub_8740 {
  strings:
    $key_8740 = { d3 28 [2] a7 30 [2] e0 32 [2] a7 23 [2] e9 2f [2] e5 25 [2] f2 2e [2] e9 60 [2] d4 }

  condition:
    any of them
}