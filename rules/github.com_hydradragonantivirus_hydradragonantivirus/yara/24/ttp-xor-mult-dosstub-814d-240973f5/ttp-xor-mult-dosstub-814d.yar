rule TTP_XOR_MULT_DOSStub_814d {
  strings:
    $key_814d = { d5 25 [2] a1 3d [2] e6 3f [2] a1 2e [2] ef 22 [2] e3 28 [2] f4 23 [2] ef 6d [2] d2 }

  condition:
    any of them
}