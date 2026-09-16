rule TTP_XOR_MULT_DOSStub_9569 {
  strings:
    $key_9569 = { c1 01 [2] b5 19 [2] f2 1b [2] b5 0a [2] fb 06 [2] f7 0c [2] e0 07 [2] fb 49 [2] c6 }

  condition:
    any of them
}