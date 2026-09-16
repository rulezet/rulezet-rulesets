rule TTP_XOR_MULT_DOSStub_957e {
  strings:
    $key_957e = { c1 16 [2] b5 0e [2] f2 0c [2] b5 1d [2] fb 11 [2] f7 1b [2] e0 10 [2] fb 5e [2] c6 }

  condition:
    any of them
}