rule TTP_XOR_MULT_DOSStub_9722 {
  strings:
    $key_9722 = { c3 4a [2] b7 52 [2] f0 50 [2] b7 41 [2] f9 4d [2] f5 47 [2] e2 4c [2] f9 02 [2] c4 }

  condition:
    any of them
}