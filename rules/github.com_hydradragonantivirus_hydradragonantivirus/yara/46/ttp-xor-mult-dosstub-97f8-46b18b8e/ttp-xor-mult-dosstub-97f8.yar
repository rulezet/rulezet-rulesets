rule TTP_XOR_MULT_DOSStub_97f8 {
  strings:
    $key_97f8 = { c3 90 [2] b7 88 [2] f0 8a [2] b7 9b [2] f9 97 [2] f5 9d [2] e2 96 [2] f9 d8 [2] c4 }

  condition:
    any of them
}