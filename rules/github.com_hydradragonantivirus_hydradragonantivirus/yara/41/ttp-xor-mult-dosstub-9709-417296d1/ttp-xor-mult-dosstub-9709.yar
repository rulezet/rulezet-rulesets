rule TTP_XOR_MULT_DOSStub_9709 {
  strings:
    $key_9709 = { c3 61 [2] b7 79 [2] f0 7b [2] b7 6a [2] f9 66 [2] f5 6c [2] e2 67 [2] f9 29 [2] c4 }

  condition:
    any of them
}