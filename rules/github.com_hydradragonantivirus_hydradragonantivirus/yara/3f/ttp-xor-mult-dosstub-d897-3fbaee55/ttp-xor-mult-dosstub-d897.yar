rule TTP_XOR_MULT_DOSStub_d897 {
  strings:
    $key_d897 = { 8c ff [2] f8 e7 [2] bf e5 [2] f8 f4 [2] b6 f8 [2] ba f2 [2] ad f9 [2] b6 b7 [2] 8b }

  condition:
    any of them
}