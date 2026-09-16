rule TTP_XOR_MULT_DOSStub_d895 {
  strings:
    $key_d895 = { 8c fd [2] f8 e5 [2] bf e7 [2] f8 f6 [2] b6 fa [2] ba f0 [2] ad fb [2] b6 b5 [2] 8b }

  condition:
    any of them
}