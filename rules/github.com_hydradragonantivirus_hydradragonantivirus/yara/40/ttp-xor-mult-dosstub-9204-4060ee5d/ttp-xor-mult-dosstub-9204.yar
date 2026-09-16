rule TTP_XOR_MULT_DOSStub_9204 {
  strings:
    $key_9204 = { c6 6c [2] b2 74 [2] f5 76 [2] b2 67 [2] fc 6b [2] f0 61 [2] e7 6a [2] fc 24 [2] c1 }

  condition:
    any of them
}