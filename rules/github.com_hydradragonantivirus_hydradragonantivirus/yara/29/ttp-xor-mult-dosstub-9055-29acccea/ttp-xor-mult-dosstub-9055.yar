rule TTP_XOR_MULT_DOSStub_9055 {
  strings:
    $key_9055 = { c4 3d [2] b0 25 [2] f7 27 [2] b0 36 [2] fe 3a [2] f2 30 [2] e5 3b [2] fe 75 [2] c3 }

  condition:
    any of them
}