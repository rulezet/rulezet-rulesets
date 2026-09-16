rule TTP_XOR_MULT_DOSStub_9114 {
  strings:
    $key_9114 = { c5 7c [2] b1 64 [2] f6 66 [2] b1 77 [2] ff 7b [2] f3 71 [2] e4 7a [2] ff 34 [2] c2 }

  condition:
    any of them
}