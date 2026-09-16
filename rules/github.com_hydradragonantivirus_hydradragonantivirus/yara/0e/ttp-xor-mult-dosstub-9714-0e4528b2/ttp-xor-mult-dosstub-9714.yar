rule TTP_XOR_MULT_DOSStub_9714 {
  strings:
    $key_9714 = { c3 7c [2] b7 64 [2] f0 66 [2] b7 77 [2] f9 7b [2] f5 71 [2] e2 7a [2] f9 34 [2] c4 }

  condition:
    any of them
}