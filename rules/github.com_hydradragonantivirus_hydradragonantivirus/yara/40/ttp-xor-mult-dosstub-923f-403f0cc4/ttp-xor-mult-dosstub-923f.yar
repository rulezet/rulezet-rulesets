rule TTP_XOR_MULT_DOSStub_923f {
  strings:
    $key_923f = { c6 57 [2] b2 4f [2] f5 4d [2] b2 5c [2] fc 50 [2] f0 5a [2] e7 51 [2] fc 1f [2] c1 }

  condition:
    any of them
}