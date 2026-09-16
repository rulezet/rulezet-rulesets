rule TTP_XOR_MULT_DOSStub_d8da {
  strings:
    $key_d8da = { 8c b2 [2] f8 aa [2] bf a8 [2] f8 b9 [2] b6 b5 [2] ba bf [2] ad b4 [2] b6 fa [2] 8b }

  condition:
    any of them
}