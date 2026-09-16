rule TTP_XOR_MULT_DOSStub_8152 {
  strings:
    $key_8152 = { d5 3a [2] a1 22 [2] e6 20 [2] a1 31 [2] ef 3d [2] e3 37 [2] f4 3c [2] ef 72 [2] d2 }

  condition:
    any of them
}