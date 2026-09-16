rule TTP_XOR_MULT_DOSStub_9238 {
  strings:
    $key_9238 = { c6 50 [2] b2 48 [2] f5 4a [2] b2 5b [2] fc 57 [2] f0 5d [2] e7 56 [2] fc 18 [2] c1 }

  condition:
    any of them
}