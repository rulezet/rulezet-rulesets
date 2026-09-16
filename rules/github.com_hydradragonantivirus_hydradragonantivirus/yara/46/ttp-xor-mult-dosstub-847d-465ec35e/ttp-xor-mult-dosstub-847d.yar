rule TTP_XOR_MULT_DOSStub_847d {
  strings:
    $key_847d = { d0 15 [2] a4 0d [2] e3 0f [2] a4 1e [2] ea 12 [2] e6 18 [2] f1 13 [2] ea 5d [2] d7 }

  condition:
    any of them
}