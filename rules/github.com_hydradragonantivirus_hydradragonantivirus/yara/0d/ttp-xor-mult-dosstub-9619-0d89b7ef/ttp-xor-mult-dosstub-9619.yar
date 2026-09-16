rule TTP_XOR_MULT_DOSStub_9619 {
  strings:
    $key_9619 = { c2 71 [2] b6 69 [2] f1 6b [2] b6 7a [2] f8 76 [2] f4 7c [2] e3 77 [2] f8 39 [2] c5 }

  condition:
    any of them
}