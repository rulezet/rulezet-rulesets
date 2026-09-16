rule TTP_XOR_MULT_DOSStub_9012 {
  strings:
    $key_9012 = { c4 7a [2] b0 62 [2] f7 60 [2] b0 71 [2] fe 7d [2] f2 77 [2] e5 7c [2] fe 32 [2] c3 }

  condition:
    any of them
}