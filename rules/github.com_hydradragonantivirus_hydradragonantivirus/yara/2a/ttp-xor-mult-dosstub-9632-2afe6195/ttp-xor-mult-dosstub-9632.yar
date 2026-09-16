rule TTP_XOR_MULT_DOSStub_9632 {
  strings:
    $key_9632 = { c2 5a [2] b6 42 [2] f1 40 [2] b6 51 [2] f8 5d [2] f4 57 [2] e3 5c [2] f8 12 [2] c5 }

  condition:
    any of them
}