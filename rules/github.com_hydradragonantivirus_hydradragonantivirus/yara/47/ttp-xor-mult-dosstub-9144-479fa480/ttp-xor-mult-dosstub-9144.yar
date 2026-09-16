rule TTP_XOR_MULT_DOSStub_9144 {
  strings:
    $key_9144 = { c5 2c [2] b1 34 [2] f6 36 [2] b1 27 [2] ff 2b [2] f3 21 [2] e4 2a [2] ff 64 [2] c2 }

  condition:
    any of them
}