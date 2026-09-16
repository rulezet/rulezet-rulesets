rule TTP_XOR_MULT_DOSStub_9005 {
  strings:
    $key_9005 = { c4 6d [2] b0 75 [2] f7 77 [2] b0 66 [2] fe 6a [2] f2 60 [2] e5 6b [2] fe 25 [2] c3 }

  condition:
    any of them
}