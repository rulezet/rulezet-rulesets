rule TTP_XOR_MULT_DOSStub_9572 {
  strings:
    $key_9572 = { c1 1a [2] b5 02 [2] f2 00 [2] b5 11 [2] fb 1d [2] f7 17 [2] e0 1c [2] fb 52 [2] c6 }

  condition:
    any of them
}