rule TTP_XOR_MULT_DOSStub_9740 {
  strings:
    $key_9740 = { c3 28 [2] b7 30 [2] f0 32 [2] b7 23 [2] f9 2f [2] f5 25 [2] e2 2e [2] f9 60 [2] c4 }

  condition:
    any of them
}