rule TTP_XOR_MULT_DOSStub_97c1 {
  strings:
    $key_97c1 = { c3 a9 [2] b7 b1 [2] f0 b3 [2] b7 a2 [2] f9 ae [2] f5 a4 [2] e2 af [2] f9 e1 [2] c4 }

  condition:
    any of them
}