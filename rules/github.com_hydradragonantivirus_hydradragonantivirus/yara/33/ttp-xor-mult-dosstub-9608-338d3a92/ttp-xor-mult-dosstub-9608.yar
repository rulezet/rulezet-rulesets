rule TTP_XOR_MULT_DOSStub_9608 {
  strings:
    $key_9608 = { c2 60 [2] b6 78 [2] f1 7a [2] b6 6b [2] f8 67 [2] f4 6d [2] e3 66 [2] f8 28 [2] c5 }

  condition:
    any of them
}