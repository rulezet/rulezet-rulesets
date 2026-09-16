rule TTP_XOR_MULT_DOSStub_813f {
  strings:
    $key_813f = { d5 57 [2] a1 4f [2] e6 4d [2] a1 5c [2] ef 50 [2] e3 5a [2] f4 51 [2] ef 1f [2] d2 }

  condition:
    any of them
}