rule TTP_XOR_MULT_DOSStub_9641 {
  strings:
    $key_9641 = { c2 29 [2] b6 31 [2] f1 33 [2] b6 22 [2] f8 2e [2] f4 24 [2] e3 2f [2] f8 61 [2] c5 }

  condition:
    any of them
}