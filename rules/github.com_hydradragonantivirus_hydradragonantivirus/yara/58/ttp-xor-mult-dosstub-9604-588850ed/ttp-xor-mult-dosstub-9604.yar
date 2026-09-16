rule TTP_XOR_MULT_DOSStub_9604 {
  strings:
    $key_9604 = { c2 6c [2] b6 74 [2] f1 76 [2] b6 67 [2] f8 6b [2] f4 61 [2] e3 6a [2] f8 24 [2] c5 }

  condition:
    any of them
}