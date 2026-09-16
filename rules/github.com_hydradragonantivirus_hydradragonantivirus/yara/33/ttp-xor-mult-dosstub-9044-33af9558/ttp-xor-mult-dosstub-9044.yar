rule TTP_XOR_MULT_DOSStub_9044 {
  strings:
    $key_9044 = { c4 2c [2] b0 34 [2] f7 36 [2] b0 27 [2] fe 2b [2] f2 21 [2] e5 2a [2] fe 64 [2] c3 }

  condition:
    any of them
}