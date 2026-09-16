rule TTP_XOR_MULT_DOSStub_d8c1 {
  strings:
    $key_d8c1 = { 8c a9 [2] f8 b1 [2] bf b3 [2] f8 a2 [2] b6 ae [2] ba a4 [2] ad af [2] b6 e1 [2] 8b }

  condition:
    any of them
}