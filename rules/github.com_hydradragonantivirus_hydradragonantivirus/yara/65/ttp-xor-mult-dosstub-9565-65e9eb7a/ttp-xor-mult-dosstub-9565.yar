rule TTP_XOR_MULT_DOSStub_9565 {
  strings:
    $key_9565 = { c1 0d [2] b5 15 [2] f2 17 [2] b5 06 [2] fb 0a [2] f7 00 [2] e0 0b [2] fb 45 [2] c6 }

  condition:
    any of them
}