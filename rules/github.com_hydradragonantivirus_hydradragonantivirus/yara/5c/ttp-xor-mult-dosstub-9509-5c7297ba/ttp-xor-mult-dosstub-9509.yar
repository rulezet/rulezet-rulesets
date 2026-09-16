rule TTP_XOR_MULT_DOSStub_9509 {
  strings:
    $key_9509 = { c1 61 [2] b5 79 [2] f2 7b [2] b5 6a [2] fb 66 [2] f7 6c [2] e0 67 [2] fb 29 [2] c6 }

  condition:
    any of them
}