rule TTP_XOR_MULT_DOSStub_814a {
  strings:
    $key_814a = { d5 22 [2] a1 3a [2] e6 38 [2] a1 29 [2] ef 25 [2] e3 2f [2] f4 24 [2] ef 6a [2] d2 }

  condition:
    any of them
}