rule TTP_XOR_MULT_DOSStub_9657 {
  strings:
    $key_9657 = { c2 3f [2] b6 27 [2] f1 25 [2] b6 34 [2] f8 38 [2] f4 32 [2] e3 39 [2] f8 77 [2] c5 }

  condition:
    any of them
}