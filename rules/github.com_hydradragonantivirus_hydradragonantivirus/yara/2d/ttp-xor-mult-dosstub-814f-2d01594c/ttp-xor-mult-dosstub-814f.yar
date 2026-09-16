rule TTP_XOR_MULT_DOSStub_814f {
  strings:
    $key_814f = { d5 27 [2] a1 3f [2] e6 3d [2] a1 2c [2] ef 20 [2] e3 2a [2] f4 21 [2] ef 6f [2] d2 }

  condition:
    any of them
}