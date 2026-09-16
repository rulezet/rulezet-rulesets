rule TTP_XOR_MULT_DOSStub_924a {
  strings:
    $key_924a = { c6 22 [2] b2 3a [2] f5 38 [2] b2 29 [2] fc 25 [2] f0 2f [2] e7 24 [2] fc 6a [2] c1 }

  condition:
    any of them
}