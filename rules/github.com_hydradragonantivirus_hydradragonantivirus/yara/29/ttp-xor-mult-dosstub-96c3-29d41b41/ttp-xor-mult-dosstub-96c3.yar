rule TTP_XOR_MULT_DOSStub_96c3 {
  strings:
    $key_96c3 = { c2 ab [2] b6 b3 [2] f1 b1 [2] b6 a0 [2] f8 ac [2] f4 a6 [2] e3 ad [2] f8 e3 [2] c5 }

  condition:
    any of them
}