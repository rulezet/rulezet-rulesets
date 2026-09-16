rule TTP_XOR_MULT_DOSStub_815f {
  strings:
    $key_815f = { d5 37 [2] a1 2f [2] e6 2d [2] a1 3c [2] ef 30 [2] e3 3a [2] f4 31 [2] ef 7f [2] d2 }

  condition:
    any of them
}