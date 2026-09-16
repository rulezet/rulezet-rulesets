rule TTP_XOR_MULT_DOSStub_817d {
  strings:
    $key_817d = { d5 15 [2] a1 0d [2] e6 0f [2] a1 1e [2] ef 12 [2] e3 18 [2] f4 13 [2] ef 5d [2] d2 }

  condition:
    any of them
}