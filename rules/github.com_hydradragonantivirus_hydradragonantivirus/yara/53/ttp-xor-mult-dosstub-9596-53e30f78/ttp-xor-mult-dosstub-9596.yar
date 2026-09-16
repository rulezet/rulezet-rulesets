rule TTP_XOR_MULT_DOSStub_9596 {
  strings:
    $key_9596 = { c1 fe [2] b5 e6 [2] f2 e4 [2] b5 f5 [2] fb f9 [2] f7 f3 [2] e0 f8 [2] fb b6 [2] c6 }

  condition:
    any of them
}