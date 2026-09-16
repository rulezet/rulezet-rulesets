rule TTP_XOR_MULT_DOSStub_9772 {
  strings:
    $key_9772 = { c3 1a [2] b7 02 [2] f0 00 [2] b7 11 [2] f9 1d [2] f5 17 [2] e2 1c [2] f9 52 [2] c4 }

  condition:
    any of them
}