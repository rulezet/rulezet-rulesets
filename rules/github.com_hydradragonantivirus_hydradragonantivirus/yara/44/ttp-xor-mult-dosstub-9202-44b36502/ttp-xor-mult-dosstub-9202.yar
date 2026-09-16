rule TTP_XOR_MULT_DOSStub_9202 {
  strings:
    $key_9202 = { c6 6a [2] b2 72 [2] f5 70 [2] b2 61 [2] fc 6d [2] f0 67 [2] e7 6c [2] fc 22 [2] c1 }

  condition:
    any of them
}