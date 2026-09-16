rule TTP_XOR_MULT_DOSStub_844d {
  strings:
    $key_844d = { d0 25 [2] a4 3d [2] e3 3f [2] a4 2e [2] ea 22 [2] e6 28 [2] f1 23 [2] ea 6d [2] d7 }

  condition:
    any of them
}