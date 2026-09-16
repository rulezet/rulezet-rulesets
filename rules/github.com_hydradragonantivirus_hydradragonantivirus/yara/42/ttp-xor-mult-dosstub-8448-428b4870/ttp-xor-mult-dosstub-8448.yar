rule TTP_XOR_MULT_DOSStub_8448 {
  strings:
    $key_8448 = { d0 20 [2] a4 38 [2] e3 3a [2] a4 2b [2] ea 27 [2] e6 2d [2] f1 26 [2] ea 68 [2] d7 }

  condition:
    any of them
}