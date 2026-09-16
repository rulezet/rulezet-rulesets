rule TTP_XOR_MULT_DOSStub_967e {
  strings:
    $key_967e = { c2 16 [2] b6 0e [2] f1 0c [2] b6 1d [2] f8 11 [2] f4 1b [2] e3 10 [2] f8 5e [2] c5 }

  condition:
    any of them
}