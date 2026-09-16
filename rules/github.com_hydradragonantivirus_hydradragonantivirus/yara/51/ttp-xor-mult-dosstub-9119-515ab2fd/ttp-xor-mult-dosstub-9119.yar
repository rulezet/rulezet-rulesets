rule TTP_XOR_MULT_DOSStub_9119 {
  strings:
    $key_9119 = { c5 71 [2] b1 69 [2] f6 6b [2] b1 7a [2] ff 76 [2] f3 7c [2] e4 77 [2] ff 39 [2] c2 }

  condition:
    any of them
}