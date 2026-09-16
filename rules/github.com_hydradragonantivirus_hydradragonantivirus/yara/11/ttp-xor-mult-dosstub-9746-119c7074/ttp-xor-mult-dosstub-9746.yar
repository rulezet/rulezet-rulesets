rule TTP_XOR_MULT_DOSStub_9746 {
  strings:
    $key_9746 = { c3 2e [2] b7 36 [2] f0 34 [2] b7 25 [2] f9 29 [2] f5 23 [2] e2 28 [2] f9 66 [2] c4 }

  condition:
    any of them
}