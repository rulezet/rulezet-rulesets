rule TTP_XOR_MULT_DOSStub_97fa {
  strings:
    $key_97fa = { c3 92 [2] b7 8a [2] f0 88 [2] b7 99 [2] f9 95 [2] f5 9f [2] e2 94 [2] f9 da [2] c4 }

  condition:
    any of them
}