rule TTP_XOR_MULT_DOSStub_865f {
  strings:
    $key_865f = { d2 37 [2] a6 2f [2] e1 2d [2] a6 3c [2] e8 30 [2] e4 3a [2] f3 31 [2] e8 7f [2] d5 }

  condition:
    any of them
}