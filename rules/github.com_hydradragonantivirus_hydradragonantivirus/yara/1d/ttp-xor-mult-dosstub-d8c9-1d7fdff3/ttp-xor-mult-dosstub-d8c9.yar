rule TTP_XOR_MULT_DOSStub_d8c9 {
  strings:
    $key_d8c9 = { 8c a1 [2] f8 b9 [2] bf bb [2] f8 aa [2] b6 a6 [2] ba ac [2] ad a7 [2] b6 e9 [2] 8b }

  condition:
    any of them
}