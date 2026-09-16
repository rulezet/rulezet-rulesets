rule TTP_XOR_MULT_DOSStub_865d {
  strings:
    $key_865d = { d2 35 [2] a6 2d [2] e1 2f [2] a6 3e [2] e8 32 [2] e4 38 [2] f3 33 [2] e8 7d [2] d5 }

  condition:
    any of them
}