rule TTP_XOR_MULT_DOSStub_9174 {
  strings:
    $key_9174 = { c5 1c [2] b1 04 [2] f6 06 [2] b1 17 [2] ff 1b [2] f3 11 [2] e4 1a [2] ff 54 [2] c2 }

  condition:
    any of them
}