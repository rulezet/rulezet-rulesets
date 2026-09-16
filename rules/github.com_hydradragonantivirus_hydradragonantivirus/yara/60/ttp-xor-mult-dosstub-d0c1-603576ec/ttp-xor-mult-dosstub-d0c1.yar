rule TTP_XOR_MULT_DOSStub_d0c1 {
  strings:
    $key_d0c1 = { 84 a9 [2] f0 b1 [2] b7 b3 [2] f0 a2 [2] be ae [2] b2 a4 [2] a5 af [2] be e1 [2] 83 }

  condition:
    any of them
}