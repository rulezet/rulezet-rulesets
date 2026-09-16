rule TTP_XOR_MULT_DOSStub_867e {
  strings:
    $key_867e = { d2 16 [2] a6 0e [2] e1 0c [2] a6 1d [2] e8 11 [2] e4 1b [2] f3 10 [2] e8 5e [2] d5 }

  condition:
    any of them
}