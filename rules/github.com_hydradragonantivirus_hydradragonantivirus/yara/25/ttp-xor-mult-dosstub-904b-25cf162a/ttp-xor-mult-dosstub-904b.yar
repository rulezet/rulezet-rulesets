rule TTP_XOR_MULT_DOSStub_904b {
  strings:
    $key_904b = { c4 23 [2] b0 3b [2] f7 39 [2] b0 28 [2] fe 24 [2] f2 2e [2] e5 25 [2] fe 6b [2] c3 }

  condition:
    any of them
}