rule TTP_XOR_MULT_DOSStub_925a {
  strings:
    $key_925a = { c6 32 [2] b2 2a [2] f5 28 [2] b2 39 [2] fc 35 [2] f0 3f [2] e7 34 [2] fc 7a [2] c1 }

  condition:
    any of them
}