rule TTP_XOR_MULT_DOSStub_9079 {
  strings:
    $key_9079 = { c4 11 [2] b0 09 [2] f7 0b [2] b0 1a [2] fe 16 [2] f2 1c [2] e5 17 [2] fe 59 [2] c3 }

  condition:
    any of them
}