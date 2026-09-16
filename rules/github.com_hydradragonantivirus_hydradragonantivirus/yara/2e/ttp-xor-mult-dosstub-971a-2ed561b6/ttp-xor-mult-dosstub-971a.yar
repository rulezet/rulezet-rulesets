rule TTP_XOR_MULT_DOSStub_971a {
  strings:
    $key_971a = { c3 72 [2] b7 6a [2] f0 68 [2] b7 79 [2] f9 75 [2] f5 7f [2] e2 74 [2] f9 3a [2] c4 }

  condition:
    any of them
}