rule TTP_XOR_MULT_DOSStub_96c0 {
  strings:
    $key_96c0 = { c2 a8 [2] b6 b0 [2] f1 b2 [2] b6 a3 [2] f8 af [2] f4 a5 [2] e3 ae [2] f8 e0 [2] c5 }

  condition:
    any of them
}