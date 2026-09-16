rule TTP_XOR_MULT_DOSStub_904a {
  strings:
    $key_904a = { c4 22 [2] b0 3a [2] f7 38 [2] b0 29 [2] fe 25 [2] f2 2f [2] e5 24 [2] fe 6a [2] c3 }

  condition:
    any of them
}