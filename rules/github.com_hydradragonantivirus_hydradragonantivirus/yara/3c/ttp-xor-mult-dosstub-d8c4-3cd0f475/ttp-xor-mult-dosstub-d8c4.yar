rule TTP_XOR_MULT_DOSStub_d8c4 {
  strings:
    $key_d8c4 = { 8c ac [2] f8 b4 [2] bf b6 [2] f8 a7 [2] b6 ab [2] ba a1 [2] ad aa [2] b6 e4 [2] 8b }

  condition:
    any of them
}