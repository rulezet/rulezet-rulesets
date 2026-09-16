rule TTP_XOR_MULT_DOSStub_961a {
  strings:
    $key_961a = { c2 72 [2] b6 6a [2] f1 68 [2] b6 79 [2] f8 75 [2] f4 7f [2] e3 74 [2] f8 3a [2] c5 }

  condition:
    any of them
}