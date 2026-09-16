rule TTP_XOR_MULT_DOSStub_9054 {
  strings:
    $key_9054 = { c4 3c [2] b0 24 [2] f7 26 [2] b0 37 [2] fe 3b [2] f2 31 [2] e5 3a [2] fe 74 [2] c3 }

  condition:
    any of them
}