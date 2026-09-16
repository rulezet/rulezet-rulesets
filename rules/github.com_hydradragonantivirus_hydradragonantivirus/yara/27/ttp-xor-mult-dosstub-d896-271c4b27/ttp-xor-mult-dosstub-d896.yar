rule TTP_XOR_MULT_DOSStub_d896 {
  strings:
    $key_d896 = { 8c fe [2] f8 e6 [2] bf e4 [2] f8 f5 [2] b6 f9 [2] ba f3 [2] ad f8 [2] b6 b6 [2] 8b }

  condition:
    any of them
}