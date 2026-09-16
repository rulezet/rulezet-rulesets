rule TTP_XOR_MULT_DOSStub_9645 {
  strings:
    $key_9645 = { c2 2d [2] b6 35 [2] f1 37 [2] b6 26 [2] f8 2a [2] f4 20 [2] e3 2b [2] f8 65 [2] c5 }

  condition:
    any of them
}