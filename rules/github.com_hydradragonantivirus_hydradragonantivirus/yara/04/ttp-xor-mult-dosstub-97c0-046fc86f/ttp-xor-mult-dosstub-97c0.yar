rule TTP_XOR_MULT_DOSStub_97c0 {
  strings:
    $key_97c0 = { c3 a8 [2] b7 b0 [2] f0 b2 [2] b7 a3 [2] f9 af [2] f5 a5 [2] e2 ae [2] f9 e0 [2] c4 }

  condition:
    any of them
}