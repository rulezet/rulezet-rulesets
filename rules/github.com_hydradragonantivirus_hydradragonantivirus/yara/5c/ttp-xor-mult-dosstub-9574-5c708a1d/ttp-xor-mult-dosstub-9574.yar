rule TTP_XOR_MULT_DOSStub_9574 {
  strings:
    $key_9574 = { c1 1c [2] b5 04 [2] f2 06 [2] b5 17 [2] fb 1b [2] f7 11 [2] e0 1a [2] fb 54 [2] c6 }

  condition:
    any of them
}