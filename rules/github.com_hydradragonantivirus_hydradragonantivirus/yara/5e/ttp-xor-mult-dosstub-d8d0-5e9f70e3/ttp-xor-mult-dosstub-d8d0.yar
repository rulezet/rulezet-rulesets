rule TTP_XOR_MULT_DOSStub_d8d0 {
  strings:
    $key_d8d0 = { 8c b8 [2] f8 a0 [2] bf a2 [2] f8 b3 [2] b6 bf [2] ba b5 [2] ad be [2] b6 f0 [2] 8b }

  condition:
    any of them
}