rule TTP_XOR_MULT_DOSStub_844f {
  strings:
    $key_844f = { d0 27 [2] a4 3f [2] e3 3d [2] a4 2c [2] ea 20 [2] e6 2a [2] f1 21 [2] ea 6f [2] d7 }

  condition:
    any of them
}