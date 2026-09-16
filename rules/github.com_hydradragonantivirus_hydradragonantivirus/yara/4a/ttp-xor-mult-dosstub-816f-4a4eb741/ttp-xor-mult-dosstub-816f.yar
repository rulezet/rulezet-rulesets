rule TTP_XOR_MULT_DOSStub_816f {
  strings:
    $key_816f = { d5 07 [2] a1 1f [2] e6 1d [2] a1 0c [2] ef 00 [2] e3 0a [2] f4 01 [2] ef 4f [2] d2 }

  condition:
    any of them
}