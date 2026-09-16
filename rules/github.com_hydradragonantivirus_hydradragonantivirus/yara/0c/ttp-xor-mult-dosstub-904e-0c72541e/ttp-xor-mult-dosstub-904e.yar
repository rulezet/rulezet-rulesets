rule TTP_XOR_MULT_DOSStub_904e {
  strings:
    $key_904e = { c4 26 [2] b0 3e [2] f7 3c [2] b0 2d [2] fe 21 [2] f2 2b [2] e5 20 [2] fe 6e [2] c3 }

  condition:
    any of them
}