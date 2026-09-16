rule TTP_XOR_MULT_DOSStub_d4c1 {
  strings:
    $key_d4c1 = { 80 a9 [2] f4 b1 [2] b3 b3 [2] f4 a2 [2] ba ae [2] b6 a4 [2] a1 af [2] ba e1 [2] 87 }

  condition:
    any of them
}