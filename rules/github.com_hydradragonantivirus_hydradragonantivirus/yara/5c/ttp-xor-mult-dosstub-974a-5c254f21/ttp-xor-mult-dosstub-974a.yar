rule TTP_XOR_MULT_DOSStub_974a {
  strings:
    $key_974a = { c3 22 [2] b7 3a [2] f0 38 [2] b7 29 [2] f9 25 [2] f5 2f [2] e2 24 [2] f9 6a [2] c4 }

  condition:
    any of them
}