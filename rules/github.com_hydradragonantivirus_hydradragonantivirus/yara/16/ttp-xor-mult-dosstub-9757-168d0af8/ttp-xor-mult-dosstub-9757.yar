rule TTP_XOR_MULT_DOSStub_9757 {
  strings:
    $key_9757 = { c3 3f [2] b7 27 [2] f0 25 [2] b7 34 [2] f9 38 [2] f5 32 [2] e2 39 [2] f9 77 [2] c4 }

  condition:
    any of them
}