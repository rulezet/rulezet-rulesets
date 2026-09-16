rule TTP_XOR_MULT_DOSStub_811a {
  strings:
    $key_811a = { d5 72 [2] a1 6a [2] e6 68 [2] a1 79 [2] ef 75 [2] e3 7f [2] f4 74 [2] ef 3a [2] d2 }

  condition:
    any of them
}