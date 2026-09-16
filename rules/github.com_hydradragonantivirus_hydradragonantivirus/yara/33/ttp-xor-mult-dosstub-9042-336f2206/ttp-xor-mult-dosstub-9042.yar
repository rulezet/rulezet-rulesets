rule TTP_XOR_MULT_DOSStub_9042 {
  strings:
    $key_9042 = { c4 2a [2] b0 32 [2] f7 30 [2] b0 21 [2] fe 2d [2] f2 27 [2] e5 2c [2] fe 62 [2] c3 }

  condition:
    any of them
}