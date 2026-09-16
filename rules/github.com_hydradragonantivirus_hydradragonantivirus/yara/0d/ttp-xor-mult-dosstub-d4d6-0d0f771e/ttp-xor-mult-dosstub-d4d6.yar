rule TTP_XOR_MULT_DOSStub_d4d6 {
  strings:
    $key_d4d6 = { 80 be [2] f4 a6 [2] b3 a4 [2] f4 b5 [2] ba b9 [2] b6 b3 [2] a1 b8 [2] ba f6 [2] 87 }

  condition:
    any of them
}