rule TTP_XOR_MULT_DOSStub_d8d8 {
  strings:
    $key_d8d8 = { 8c b0 [2] f8 a8 [2] bf aa [2] f8 bb [2] b6 b7 [2] ba bd [2] ad b6 [2] b6 f8 [2] 8b }

  condition:
    any of them
}