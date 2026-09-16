rule TTP_XOR_MULT_DOSStub_9179 {
  strings:
    $key_9179 = { c5 11 [2] b1 09 [2] f6 0b [2] b1 1a [2] ff 16 [2] f3 1c [2] e4 17 [2] ff 59 [2] c2 }

  condition:
    any of them
}