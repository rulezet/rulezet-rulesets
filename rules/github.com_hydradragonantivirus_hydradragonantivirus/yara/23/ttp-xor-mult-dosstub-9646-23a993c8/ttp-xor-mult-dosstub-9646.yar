rule TTP_XOR_MULT_DOSStub_9646 {
  strings:
    $key_9646 = { c2 2e [2] b6 36 [2] f1 34 [2] b6 25 [2] f8 29 [2] f4 23 [2] e3 28 [2] f8 66 [2] c5 }

  condition:
    any of them
}