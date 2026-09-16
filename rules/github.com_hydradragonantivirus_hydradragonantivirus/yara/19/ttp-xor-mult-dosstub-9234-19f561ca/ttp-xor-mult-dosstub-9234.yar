rule TTP_XOR_MULT_DOSStub_9234 {
  strings:
    $key_9234 = { c6 5c [2] b2 44 [2] f5 46 [2] b2 57 [2] fc 5b [2] f0 51 [2] e7 5a [2] fc 14 [2] c1 }

  condition:
    any of them
}