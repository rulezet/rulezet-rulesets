rule TTP_XOR_MULT_DOSStub_92e2 {
  strings:
    $key_92e2 = { c6 8a [2] b2 92 [2] f5 90 [2] b2 81 [2] fc 8d [2] f0 87 [2] e7 8c [2] fc c2 [2] c1 }

  condition:
    any of them
}