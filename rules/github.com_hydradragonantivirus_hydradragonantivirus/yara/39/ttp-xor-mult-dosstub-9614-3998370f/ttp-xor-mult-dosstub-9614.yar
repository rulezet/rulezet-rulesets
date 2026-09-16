rule TTP_XOR_MULT_DOSStub_9614 {
  strings:
    $key_9614 = { c2 7c [2] b6 64 [2] f1 66 [2] b6 77 [2] f8 7b [2] f4 71 [2] e3 7a [2] f8 34 [2] c5 }

  condition:
    any of them
}