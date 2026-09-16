rule TTP_XOR_MULT_DOSStub_847e {
  strings:
    $key_847e = { d0 16 [2] a4 0e [2] e3 0c [2] a4 1d [2] ea 11 [2] e6 1b [2] f1 10 [2] ea 5e [2] d7 }

  condition:
    any of them
}