rule TTP_XOR_MULT_DOSStub_9032 {
  strings:
    $key_9032 = { c4 5a [2] b0 42 [2] f7 40 [2] b0 51 [2] fe 5d [2] f2 57 [2] e5 5c [2] fe 12 [2] c3 }

  condition:
    any of them
}