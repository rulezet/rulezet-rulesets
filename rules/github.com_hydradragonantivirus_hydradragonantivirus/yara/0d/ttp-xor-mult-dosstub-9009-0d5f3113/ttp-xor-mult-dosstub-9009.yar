rule TTP_XOR_MULT_DOSStub_9009 {
  strings:
    $key_9009 = { c4 61 [2] b0 79 [2] f7 7b [2] b0 6a [2] fe 66 [2] f2 6c [2] e5 67 [2] fe 29 [2] c3 }

  condition:
    any of them
}