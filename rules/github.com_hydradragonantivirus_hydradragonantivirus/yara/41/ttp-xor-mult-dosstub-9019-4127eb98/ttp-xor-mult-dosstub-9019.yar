rule TTP_XOR_MULT_DOSStub_9019 {
  strings:
    $key_9019 = { c4 71 [2] b0 69 [2] f7 6b [2] b0 7a [2] fe 76 [2] f2 7c [2] e5 77 [2] fe 39 [2] c3 }

  condition:
    any of them
}