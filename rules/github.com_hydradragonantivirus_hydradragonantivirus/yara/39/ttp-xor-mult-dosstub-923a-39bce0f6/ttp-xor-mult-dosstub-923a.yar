rule TTP_XOR_MULT_DOSStub_923a {
  strings:
    $key_923a = { c6 52 [2] b2 4a [2] f5 48 [2] b2 59 [2] fc 55 [2] f0 5f [2] e7 54 [2] fc 1a [2] c1 }

  condition:
    any of them
}