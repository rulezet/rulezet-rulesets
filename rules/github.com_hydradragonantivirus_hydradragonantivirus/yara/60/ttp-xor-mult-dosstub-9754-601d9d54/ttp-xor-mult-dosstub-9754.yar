rule TTP_XOR_MULT_DOSStub_9754 {
  strings:
    $key_9754 = { c3 3c [2] b7 24 [2] f0 26 [2] b7 37 [2] f9 3b [2] f5 31 [2] e2 3a [2] f9 74 [2] c4 }

  condition:
    any of them
}