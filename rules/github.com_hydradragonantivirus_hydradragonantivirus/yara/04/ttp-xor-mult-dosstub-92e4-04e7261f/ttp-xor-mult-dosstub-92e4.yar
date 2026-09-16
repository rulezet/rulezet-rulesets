rule TTP_XOR_MULT_DOSStub_92e4 {
  strings:
    $key_92e4 = { c6 8c [2] b2 94 [2] f5 96 [2] b2 87 [2] fc 8b [2] f0 81 [2] e7 8a [2] fc c4 [2] c1 }

  condition:
    any of them
}