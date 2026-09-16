rule TTP_XOR_MULT_DOSStub_9259 {
  strings:
    $key_9259 = { c6 31 [2] b2 29 [2] f5 2b [2] b2 3a [2] fc 36 [2] f0 3c [2] e7 37 [2] fc 79 [2] c1 }

  condition:
    any of them
}