rule TTP_XOR_MULT_DOSStub_9562 {
  strings:
    $key_9562 = { c1 0a [2] b5 12 [2] f2 10 [2] b5 01 [2] fb 0d [2] f7 07 [2] e0 0c [2] fb 42 [2] c6 }

  condition:
    any of them
}