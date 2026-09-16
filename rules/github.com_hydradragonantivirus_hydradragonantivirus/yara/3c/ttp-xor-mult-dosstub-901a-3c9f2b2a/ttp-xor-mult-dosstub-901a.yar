rule TTP_XOR_MULT_DOSStub_901a {
  strings:
    $key_901a = { c4 72 [2] b0 6a [2] f7 68 [2] b0 79 [2] fe 75 [2] f2 7f [2] e5 74 [2] fe 3a [2] c3 }

  condition:
    any of them
}