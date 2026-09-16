rule TTP_XOR_MULT_DOSStub_96c8 {
  strings:
    $key_96c8 = { c2 a0 [2] b6 b8 [2] f1 ba [2] b6 ab [2] f8 a7 [2] f4 ad [2] e3 a6 [2] f8 e8 [2] c5 }

  condition:
    any of them
}