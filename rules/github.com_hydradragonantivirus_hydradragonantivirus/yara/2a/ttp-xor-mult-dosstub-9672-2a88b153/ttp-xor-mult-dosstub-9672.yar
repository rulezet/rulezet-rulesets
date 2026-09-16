rule TTP_XOR_MULT_DOSStub_9672 {
  strings:
    $key_9672 = { c2 1a [2] b6 02 [2] f1 00 [2] b6 11 [2] f8 1d [2] f4 17 [2] e3 1c [2] f8 52 [2] c5 }

  condition:
    any of them
}