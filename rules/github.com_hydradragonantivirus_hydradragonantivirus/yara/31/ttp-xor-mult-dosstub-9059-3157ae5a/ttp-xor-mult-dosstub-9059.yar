rule TTP_XOR_MULT_DOSStub_9059 {
  strings:
    $key_9059 = { c4 31 [2] b0 29 [2] f7 2b [2] b0 3a [2] fe 36 [2] f2 3c [2] e5 37 [2] fe 79 [2] c3 }

  condition:
    any of them
}