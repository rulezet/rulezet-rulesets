rule TTP_XOR_MULT_DOSStub_9544 {
  strings:
    $key_9544 = { c1 2c [2] b5 34 [2] f2 36 [2] b5 27 [2] fb 2b [2] f7 21 [2] e0 2a [2] fb 64 [2] c6 }

  condition:
    any of them
}