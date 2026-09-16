rule TTP_XOR_MULT_DOSStub_92e9 {
  strings:
    $key_92e9 = { c6 81 [2] b2 99 [2] f5 9b [2] b2 8a [2] fc 86 [2] f0 8c [2] e7 87 [2] fc c9 [2] c1 }

  condition:
    any of them
}