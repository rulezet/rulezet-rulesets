rule TTP_XOR_MULT_DOSStub_9718 {
  strings:
    $key_9718 = { c3 70 [2] b7 68 [2] f0 6a [2] b7 7b [2] f9 77 [2] f5 7d [2] e2 76 [2] f9 38 [2] c4 }

  condition:
    any of them
}