rule TTP_XOR_MULT_DOSStub_9734 {
  strings:
    $key_9734 = { c3 5c [2] b7 44 [2] f0 46 [2] b7 57 [2] f9 5b [2] f5 51 [2] e2 5a [2] f9 14 [2] c4 }

  condition:
    any of them
}