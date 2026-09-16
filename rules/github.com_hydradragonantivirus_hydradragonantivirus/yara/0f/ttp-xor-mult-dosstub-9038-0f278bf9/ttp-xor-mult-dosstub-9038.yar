rule TTP_XOR_MULT_DOSStub_9038 {
  strings:
    $key_9038 = { c4 50 [2] b0 48 [2] f7 4a [2] b0 5b [2] fe 57 [2] f2 5d [2] e5 56 [2] fe 18 [2] c3 }

  condition:
    any of them
}