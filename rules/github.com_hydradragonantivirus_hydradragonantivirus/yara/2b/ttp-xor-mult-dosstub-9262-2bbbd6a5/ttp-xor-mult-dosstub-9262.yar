rule TTP_XOR_MULT_DOSStub_9262 {
  strings:
    $key_9262 = { c6 0a [2] b2 12 [2] f5 10 [2] b2 01 [2] fc 0d [2] f0 07 [2] e7 0c [2] fc 42 [2] c1 }

  condition:
    any of them
}