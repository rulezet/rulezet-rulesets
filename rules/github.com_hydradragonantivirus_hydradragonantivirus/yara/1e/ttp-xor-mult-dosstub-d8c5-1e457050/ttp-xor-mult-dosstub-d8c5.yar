rule TTP_XOR_MULT_DOSStub_d8c5 {
  strings:
    $key_d8c5 = { 8c ad [2] f8 b5 [2] bf b7 [2] f8 a6 [2] b6 aa [2] ba a0 [2] ad ab [2] b6 e5 [2] 8b }

  condition:
    any of them
}