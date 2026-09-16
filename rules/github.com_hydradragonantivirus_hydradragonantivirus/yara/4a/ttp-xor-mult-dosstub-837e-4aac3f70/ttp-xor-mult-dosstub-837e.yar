rule TTP_XOR_MULT_DOSStub_837e {
  strings:
    $key_837e = { d7 16 [2] a3 0e [2] e4 0c [2] a3 1d [2] ed 11 [2] e1 1b [2] f6 10 [2] ed 5e [2] d0 }

  condition:
    any of them
}