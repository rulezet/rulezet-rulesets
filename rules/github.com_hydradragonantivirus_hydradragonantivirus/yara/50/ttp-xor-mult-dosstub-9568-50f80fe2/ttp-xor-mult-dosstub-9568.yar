rule TTP_XOR_MULT_DOSStub_9568 {
  strings:
    $key_9568 = { c1 00 [2] b5 18 [2] f2 1a [2] b5 0b [2] fb 07 [2] f7 0d [2] e0 06 [2] fb 48 [2] c6 }

  condition:
    any of them
}